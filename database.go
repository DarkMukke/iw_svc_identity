package main

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"log"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

type DatabaseParameters struct {
	hostname string
	port     string
	name     string
	timeout  time.Duration
}

// DatabaseCredentials is a set of dynamic credentials retrieved from Vault
type DatabaseCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Database struct {
	connection      *sql.DB
	connectionMutex sync.Mutex
	parameters      DatabaseParameters
}

type User struct {
	bun.BaseModel `bun:"table:identity_users,alias:u"`

	ID                  uuid.UUID `bun:",pk,type:uuid,default:uuid_generate_v4()" json:"id"`
	DiscordToken        string    `bun:"discord_token" json:"discord_token"`
	DiscordExpiresIn    int32     `bun:"discord_expires_in" json:"discord_expires_in"`
	DiscordRefreshToken string    `bun:"discord_refresh_token" json:"discord_refresh_token"`
	Email               string    `bun:"email" json:"email"`
	Nickname            string    `bun:"nickname" json:"nickname"`
	IdentityToken       string    `bun:"identity_token" json:"identity_token"`
	Roles               []string  `bun:",array" json:"roles"`

	CreatedAt time.Time `bun:",nullzero,notnull,default:current_timestamp" json:"created_at"`
	UpdatedAt time.Time `bun:",nullzero,notnull,default:current_timestamp" json:"updated_at"`
}

type Player struct {
	bun.BaseModel `bun:"table:identity_players,alias:p"`

	ID            uuid.UUID `bun:",pk,type:uuid,default:uuid_generate_v4()" json:"id"`
	UserID        *User     `bun:"type:uuid,rel:belongs-to,join:user_id=id" json:"user_id"`
	RoundID       *Round    `bun:"type:uuid,rel:belongs-to,join:round_id=id" json:"round_id"`
	IdentityToken string    `bun:"identity_token" json:"identity_token"`
	Roles         []string  `bun:",array" json:"roles"`

	CreatedAt time.Time `bun:",nullzero,notnull,default:current_timestamp" json:"created_at"`
	UpdatedAt time.Time `bun:",nullzero,notnull,default:current_timestamp" json:"updated_at"`
}

type Round struct {
	bun.BaseModel `bun:"table:game_rounds,alias:r"`

	ID   uuid.UUID `bun:",pk,type:uuid,default:uuid_generate_v4()" json:"id"`
	Name string    `bun:"name" json:"name"`
}

var _ bun.BeforeAppendModelHook = (*User)(nil)
var _ bun.BeforeAppendModelHook = (*Player)(nil)

func (u *User) BeforeAppendModel(ctx context.Context, query bun.Query) error {
	switch query.(type) {
	case *bun.InsertQuery:
		u.CreatedAt = time.Now()
	case *bun.UpdateQuery:
		u.UpdatedAt = time.Now()
	}
	return nil
}
func (p *Player) BeforeAppendModel(ctx context.Context, query bun.Query) error {
	switch query.(type) {
	case *bun.InsertQuery:
		p.CreatedAt = time.Now()
	case *bun.UpdateQuery:
		p.UpdatedAt = time.Now()
	}
	return nil
}

type Product struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// NewDatabase establishes a database connection with the given Vault credentials
func NewDatabase(ctx context.Context, parameters DatabaseParameters, credentials DatabaseCredentials) (*Database, error) {
	database := &Database{
		connection:      nil,
		connectionMutex: sync.Mutex{},
		parameters:      parameters,
	}

	// establish the first connection
	if err := database.Reconnect(ctx, credentials); err != nil {
		return nil, err
	}

	return database, nil
}

// Reconnect will be called periodically to refresh the database connection
// since the dynamic credentials expire after some time, it will:
//  1. construct a connection string using the given credentials
//  2. establish a database connection
//  3. close & replace the existing connection with the new one behind a mutex
func (db *Database) Reconnect(ctx context.Context, credentials DatabaseCredentials) error {
	ctx, cancelContextFunc := context.WithTimeout(ctx, db.parameters.timeout)
	defer cancelContextFunc()

	log.Printf(
		"connecting to %q database @ %s:%s with username %q",
		db.parameters.name,
		db.parameters.hostname,
		db.parameters.port,
		credentials.Username,
	)

	connectionString := fmt.Sprintf(
		"host=%s port=%s dbname=%s user=%s password=%s sslmode=disable",
		db.parameters.hostname,
		db.parameters.port,
		db.parameters.name,
		credentials.Username,
		credentials.Password,
	)

	connection, err := sql.Open("postgres", connectionString)
	if err != nil {
		return fmt.Errorf("unable to open database connection: %w", err)
	}

	// wait until the database is ready or timeout expires
	for {
		err = connection.Ping()
		if err == nil {
			break
		}
		select {
		case <-time.After(500 * time.Millisecond):
			continue
		case <-ctx.Done():
			return fmt.Errorf("failed to successfully ping database before context timeout: %w", err)
		}
	}

	db.closeReplaceConnection(connection)

	log.Printf("connecting to %q database: success!", db.parameters.name)

	return nil
}

func (db *Database) closeReplaceConnection(new *sql.DB) {
	/* */ db.connectionMutex.Lock()
	defer db.connectionMutex.Unlock()

	// close the existing connection, if exists
	if db.connection != nil {
		_ = db.connection.Close()
	}

	// replace with a new connection
	db.connection = new
}

func (db *Database) Close() error {
	/* */ db.connectionMutex.Lock()
	defer db.connectionMutex.Unlock()

	if db.connection != nil {
		return db.connection.Close()
	}

	return nil
}

// GetProducts is a simple query function to demonstrate that we have
// successfully established a database connection with the credentials from
// Vault
func (db *Database) GetProducts(ctx context.Context) ([]Product, error) {
	/* */ db.connectionMutex.Lock()
	defer db.connectionMutex.Unlock()

	const query = "SELECT id, name FROM products"

	rows, err := db.connection.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to execute %q query: %w", query, err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var products []Product

	for rows.Next() {
		var p Product
		if err := rows.Scan(
			&p.ID,
			&p.Name,
		); err != nil {
			return nil, fmt.Errorf("failed to scan table row for %q query: %w", query, err)
		}
		products = append(products, p)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error after scanning %q query: %w", query, err)
	}

	return products, nil
}
