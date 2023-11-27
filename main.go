package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/bwmarrin/discordgo"
	"github.com/fvbock/endless"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jessevdk/go-flags"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type Environment struct {
	// The address of this service
	SvcPort string `env:"PORT"                          default:":8080"                        description:"Listen to http traffic on this tcp port" long:"svc-port"`
	SvcHost string `env:"HOST"                          default:":https://www.itswar.be"       description:"The hostname for OAuth2 callbacks" long:"svc-host"`

	// Vault address, login credentials, and secret locations
	VaultAddress           string `env:"VAULT_ADDR"                    default:"https://vault.default:8200"   description:"Vault address"                                          long:"vault-address"`
	VaultServiceAccount    string `env:"SA_NAME"                       default:"iw_core_app"                  description:"Service Account Name to log in to Vault"                long:"vault-service-account"`
	VaultDatabaseCredsPath string `env:"VAULT_DATABASE_CREDS_PATH"     default:"database/creds/core-app"      description:"Temporary database credentials will be generated here"  long:"vault-database-creds-path"`

	RedisAddr     string `env:"REDIS_ADDR"                    default:"http://redis.default:6379"    description:"Temporary database credentials will be generated here"  long:"vault-database-creds-path"`
	RedisPassword string `env:"REDIS_PASSWORD"                required:"true"                        description:"Temporary database credentials will be generated here"  long:"vault-database-creds-path"`

	// We will connect to this database using Vault-generated dynamic credentials
	DatabaseHostname string        `env:"DATABASE_HOSTNAME"             required:"true"                       description:"PostgreSQL database hostname"                           long:"database-hostname"`
	DatabasePort     string        `env:"DATABASE_PORT"                 default:"5432"                        description:"PostgreSQL database port"                               long:"database-port"`
	DatabaseName     string        `env:"DATABASE_NAME"                 default:"postgres"                    description:"PostgreSQL database name"                               long:"database-name"`
	DatabaseTimeout  time.Duration `env:"DATABASE_TIMEOUT"              default:"10s"                         description:"PostgreSQL database connection timeout"                 long:"database-timeout"`

	// Discord variables
	AllowedDomains      string `env:"ALLOWED_DOMAINS"       required:"true"                                 description:"Domains allowed to redirect to after OAuth2 login"  long:"allowed-domains"`
	RedirectUri         string `env:"REDIRECT_URI"          default:"https://www.itswar.be"                 description:"Default url to redirect to after login attempt"     long:"redirect-url"`
	DiscordClientId     string `env:"DISCORD_CLIENT_ID"     required:"true"                                 description:"Discord Client ID"                                  long:"discord-client-id"`
	DiscordClientSecret string `env:"DISCORD_CLIENT_SECRET" required:"true"                                 description:"Discord Client Secret"                              long:"discord-client-secret"`
	DiscordApiUrl       string `env:"DISCORD_API"           default:"https://discord.com/api/v10"           description:"Override for the Discord API url"                   long:"discord-api"`
	DiscordOAuthUrl     string `env:"DISCORD_OAUTH"         default:"https://discord.com/oauth2/authorize"  description:"Override for the Discord OAuth2 url"                long:"discord-oauth"`
	DiscordGuildId      string `env:"DISCORD_GUILD_ID"      default:"295117232030220288"                    description:"Override for the Discord Guild ID"                long:"discord-guild-id"`
}

type DiscordState struct {
	Action   string
	Redirect string
}

func main() {

	var env Environment
	ctx := context.Background()
	discordSateMap := make(map[string]DiscordState)
	context.WithValue(ctx, "discordSateMap", &discordSateMap)

	// parse & validate environment variables
	_, err := flags.Parse(&env)
	if err != nil {
		if flags.WroteHelp(err) {
			os.Exit(0)
		}
		log.Fatalf("unable to parse environment variables: %v", err)
	}

	api(ctx, env)

}

func api(ctx context.Context, e Environment) error {

	ctx, cancelContextFunc := context.WithCancel(ctx)
	defer cancelContextFunc()

	redisClient := NewRedisClient(ctx, RedisParameters{
		address:  e.RedisAddr,
		password: e.RedisPassword,
		database: 0,
	})

	vault, authToken, err := NewVaultClient(
		ctx,
		Parameters{
			address:                 e.VaultAddress,
			databaseCredentialsPath: e.VaultDatabaseCredsPath,
		},
	)
	if err != nil {
		return fmt.Errorf("unable to initialize vault connection @ %s: %w", e.VaultAddress, err)
	}

	err = vault.setup(ctx)
	if err != nil {
		return fmt.Errorf("unable to setup Vault Identities : %w", err)
	}

	databaseCredentials, databaseCredentialsLease, err := vault.GetDatabaseCredentials(ctx)
	if err != nil {
		return fmt.Errorf("unable to retrieve database credentials from vault: %w", err)
	}

	database, err := NewDatabase(
		ctx,
		DatabaseParameters{
			hostname: e.DatabaseHostname,
			port:     e.DatabasePort,
			name:     e.DatabaseName,
			timeout:  e.DatabaseTimeout,
		},
		databaseCredentials,
	)
	if err != nil {
		return fmt.Errorf("unable to connect to database @ %s:%s: %w", e.DatabaseHostname, e.DatabasePort, err)
	}
	defer func() {
		_ = database.Close()
	}()

	// start the lease-renewal goroutine & wait for it to finish on exit
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		vault.PeriodicallyRenewLeases(ctx, authToken, databaseCredentialsLease, database.Reconnect)
		wg.Done()
	}()
	defer func() {
		cancelContextFunc()
		wg.Wait()
	}()

	r := gin.New()
	r.Use(
		gin.LoggerWithWriter(gin.DefaultWriter, "/healthcheck"), // don't log healthcheck requests
	)

	// healthcheck
	r.GET("/healthcheck", func(c *gin.Context) {
		c.String(200, "OK")
	})

	//handle login request from the UI
	r.GET("/login/discord", func(c *gin.Context) {
		discordLogin(c, e, *redisClient)
	})
	//handle the callback from discord
	r.GET("/callback/discord", func(c *gin.Context) {
		user, redirect := discordCallback(c, e, *redisClient)
		jwt := vault.createUserIdentity(&user)
		cookieDuration, _ := time.ParseDuration("720h")
		c.SetSameSite(http.SameSiteLaxMode)
		domains := strings.Split(e.AllowedDomains, ",")
		for _, domain := range domains {
			// set the cookie on each domain in case we later have instances like dev.itswar.be test.itswar.be etc, and thus establishing SSO
			c.SetCookie("identity_user", jwt, int(cookieDuration.Seconds()), "/", domain, false, false)
		}
		c.Redirect(http.StatusFound, redirect)
	})

	endless.ListenAndServe(e.SvcPort, r)

	return nil
}

func discordLogin(c *gin.Context, e Environment, redisClient Redis) {
	q := c.Request.URL.Query()
	redirect := q["redirect"][0]
	if redirect == "" {
		redirect = e.RedirectUri
	}
	newState := uuid.New().String()
	newStateMap := DiscordState{
		Action:   "/login/Discord",
		Redirect: redirect,
	}
	duration, _ := time.ParseDuration("10m") // only store the state for 10 min, the call back should not take longer than that
	_ = redisClient.set(newState, newStateMap, duration)

	discordGrantUrlParams := url.Values{}
	discordGrantUrlParams.Add("response_type", "code")
	discordGrantUrlParams.Add("client_id", e.DiscordClientId)
	discordGrantUrlParams.Add("scope", "identity email guilds guilds.join guilds.members.read")
	discordGrantUrlParams.Add("state", newState)
	discordGrantUrlParams.Add("redirect_uri", e.SvcHost+"/callback/discord")
	discordGrantUrlParams.Add("prompt", "none")
	discordGrantUrl := e.DiscordOAuthUrl + "?" + discordGrantUrlParams.Encode()

	c.Redirect(http.StatusFound, discordGrantUrl)
}

type DiscordTokenRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	GrantType    string `json:"grant_type"`
	Code         string `json:"code"`
	RedirectUri  string `json:"redirect_uri"`
}

type DiscordTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int32  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

func discordCallback(c *gin.Context, e Environment, redisClient Redis) (User, string) {

	user := User{}

	q := c.Request.URL.Query()
	code := q["code"][0]
	state := q["state"][0]
	if state == "" || code == "" {
		c.Redirect(http.StatusFound, e.RedirectUri+"/error?e=discord_no_code_or_state")
		return user, e.RedirectUri
	}
	redisResult, err := redisClient.get(state)
	// cast the interface result into our type
	discordState, ok := redisResult.(DiscordState)
	if !ok || discordState == (DiscordState{}) {
		// we have no such state
		c.Redirect(http.StatusFound, e.RedirectUri+"/error?e=discord_invalid_state")
		return user, e.RedirectUri
	}

	// let's use the code to get the user token
	// JSON body
	body := DiscordTokenRequest{
		ClientID:     e.DiscordClientId,
		ClientSecret: e.DiscordClientSecret,
		GrantType:    "authorization_code",
		Code:         code,
		RedirectUri:  discordState.Redirect,
	}
	payloadBuf := new(bytes.Buffer)
	_ = json.NewEncoder(payloadBuf).Encode(body)
	// Exchange the code for the user token
	client := http.Client{}
	req, err := http.NewRequest("POST", e.DiscordApiUrl+"/oauth2/token", payloadBuf)
	if err != nil {
		c.Redirect(http.StatusFound, e.RedirectUri+"/error?e=discord_code_request_no_http")
		return user, e.RedirectUri
	}
	req.Header = http.Header{
		"Content-Type": {"application/x-www-form-urlencoded"},
	}

	res, err := client.Do(req)
	if err != nil {
		c.Redirect(http.StatusFound, e.RedirectUri+"/error?e=discord_token_request_500&msg="+url.QueryEscape(fmt.Sprintf("%v", err)))
		return user, e.RedirectUri
	}
	defer res.Body.Close()
	response, err := io.ReadAll(res.Body)
	if err != nil {
		c.Redirect(http.StatusFound, e.RedirectUri+"/error?e=discord_token_request_no_body")
		return user, e.RedirectUri
	}
	var tokenResponse DiscordTokenResponse
	err = json.Unmarshal(response, &tokenResponse)
	if err != nil {
		c.Redirect(http.StatusFound, e.RedirectUri+"/error?e=discord_token_request_no_marshal")
		return user, e.RedirectUri
	}

	// right now lets put all that in the database model
	user.DiscordToken = tokenResponse.AccessToken
	user.DiscordExpiresIn = tokenResponse.ExpiresIn
	user.DiscordRefreshToken = tokenResponse.RefreshToken

	//lets lookup the remaining data from discord
	discord, err := discordgo.New("Bearer " + tokenResponse.AccessToken)
	discordBot, err := discordgo.New("Bot " + e.DiscordClientSecret)
	discordUser, err := discord.User("@me")
	user.Email = discordUser.Email

	guildParams := discordgo.GuildMemberAddParams{
		AccessToken: tokenResponse.AccessToken,
		Nick:        "",
		Roles:       nil,
		Mute:        false,
		Deaf:        false,
	}
	// use the bot to add the user to the guild, this doesn't fail even if the user is already in the guild
	_ = discordBot.GuildMemberAdd(e.DiscordGuildId, discordUser.ID, &guildParams)

	discordGuild, err := discord.UserGuildMember(e.DiscordGuildId)
	user.Nickname = discordGuild.Nick

	return user, discordState.Redirect
}

type MyType struct {
	test string
}

func myFunc(a MyType) {

}

func myFuncAlse() {
	myFuncAlse(nil)
}
