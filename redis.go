package main

import (
	"context"
	"encoding/json"
	redis "github.com/redis/go-redis/v9"
	"time"
)

type Redis struct {
	client     *redis.Client
	parameters RedisParameters
	context    context.Context
}

type RedisParameters struct {
	// connection parameters
	address  string
	password string
	database int
}

func NewRedisClient(ctx context.Context, p RedisParameters) *Redis {
	client := redis.NewClient(&redis.Options{
		Addr:     p.address,
		Password: p.password, // no password set
		DB:       p.database, // use default DB
	})
	return &Redis{
		client:     client,
		parameters: p,
		context:    ctx,
	}
}

func (c *Redis) set(key string, value interface{}, duration time.Duration) error {
	p, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return c.client.Set(c.context, key, p, duration).Err()
}

func (c *Redis) get(key string) (interface{}, error) {
	val, err := c.client.Get(c.context, key).Result()
	if err != nil {
		return nil, err
	}
	var output interface{}
	err = json.Unmarshal([]byte(val), &output)
	return output, err
}
