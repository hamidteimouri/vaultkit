package vaultkit

import (
	"context"
	"fmt"
	"sync"

	vault "github.com/hashicorp/vault/api"
)

type Client struct {
	vaultClient *vault.Client
	mu          sync.Mutex
}

// NewWithToken initializes Vault client using static token
func NewWithToken(address, token string) (*Client, error) {
	cfg := vault.DefaultConfig()
	cfg.Address = address

	c, err := vault.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	c.SetToken(token)
	return &Client{vaultClient: c}, nil
}

// NewWithAppRole initializes Vault client using role_id and secret_id (AppRole auth)
func NewWithAppRole(address, roleID, secretID string) (*Client, error) {
	cfg := vault.DefaultConfig()
	cfg.Address = address

	c, err := vault.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	// Login via AppRole
	secret, err := c.Logical().Write("auth/approle/login", map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to login via approle: %w", err)
	}
	if secret == nil || secret.Auth == nil {
		return nil, fmt.Errorf("approle login returned empty auth")
	}

	c.SetToken(secret.Auth.ClientToken)
	return &Client{vaultClient: c}, nil
}

// GetSecret reads secret data from Vault (KV v2)
func (vc *Client) GetSecret(mountPath, secretPath string) (map[string]interface{}, error) {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	kv := vc.vaultClient.KVv2(mountPath)
	secret, err := kv.Get(context.Background(), secretPath)
	if err != nil {
		return nil, fmt.Errorf("vault get error: %w", err)
	}

	return secret.Data, nil
}
