package types

import (
	log "github.com/Sirupsen/logrus"
	"github.com/contiv/ccn_proxy/common/errors"
)

const (
	// TenantClaimKey is a prefix added to Claim keys in the
	// authorization or token object to represent tenants
	TenantClaimKey = "tenant:"
)

// ADConfiguration entry
//
// Fields:
//  Server: FQDN or IP address of AD server
//  Port: listening port of AD server
//  BaseDN: Distinguished name for base entity. E.g.,
//    dc=ccn, dc=example, dc=com. All searches be scoped to this BaseDN
//  ServiceAccountDN: service account details. Requires full DN. Our system
//    will use this account to communicate with AD. Hence this
//    account must have appropriate privileges, specifically for lookup
//  ServiceAccountPassword: password of the service account
//  StartTLS: if set, connection with AD will be established using TLS
//  InsecureSkipVerify: if set, skips insecurity verification
//
type ADConfiguration struct {
	Server                 string
	Port                   uint16
	BaseDN                 string
	ServiceAccountDN       string
	ServiceAccountPassword string `sql:"size:4096"`
	StartTLS               bool
	InsecureSkipVerify     bool
}

// RoleType each role type is associated with a group and set of capabilities
type RoleType uint

// Set of pre-defined roles here
const (
	Admin   RoleType = iota // can perform any operation
	Ops                     // restricted to only assigned tenants
	Invalid                 // Invalid role, this needs to be the last role
)

// Tenant is a type to represent the name of the tenant in CCN
type Tenant string

// String returns the string representation of `RoleType`
func (role RoleType) String() string {
	switch role {
	case Ops:
		return "ops"
	case Admin:
		return "admin"
	default:
		log.Debug("Illegal role type")
		return ""
	}
}

// Role returns the `RoleType` of given string
func Role(roleStr string) (RoleType, error) {
	switch roleStr {
	case Admin.String():
		return Admin, nil
	case Ops.String():
		return Ops, nil
	default:
		log.Debug("Illegal role")
		return Invalid, errors.ErrIllegalArgument
	}

}

// LocalUser information
//
// Fields:
//  UserName: of the user. Read only field. Must be unique.
//  Password: of the user. Not stored anywhere. Used only for updates.
//  Disable: if authorizations for this local user is disabled.
//  PasswordHash: of the password string.
//
type LocalUser struct {
	Username     string `json:"username"`
	Password     string `json:"password,omitempty"`
	Disable      bool   `json:"disable"`
	PasswordHash []byte `json:"password_hash,omitempty"`
}

// KVStoreConfig encapsulates config data that determines KV store
// details specific to a running instance of CCN_proxy
//
// Fields:
//   StoreURL: URL of the distributed key-value store
//             that will be shared by CCN proxy and CCN
//
type KVStoreConfig struct {
	StoreURL string `json:"kvstore-url"`
}

//
// WatchState encapsulates changes in the state stored in the KV store
// and constitutes both the current and previous state
//
// Fields:
//   Curr: current state for a key in the KV store
//   Prec: previous state for a key in the KV store
//
type WatchState struct {
	Curr State
	Prev State
}

//
// CommonState defines the fields common to all types.State
// implementations. This struct will be embedded as an anonymous
// field in all structs that implement types.State
//
// Fields:
//   StateDriver: etcd or consul statedriver
//   ID:          identifier for the state
//
type CommonState struct {
	StateDriver StateDriver `json:"-"`
	ID          string      `json:"id"`
}
