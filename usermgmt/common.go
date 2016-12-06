package usermgmt

import (
	"encoding/json"
	"fmt"

	ccnerrors "github.com/contiv/ccn_proxy/common/errors"
	"github.com/contiv/ccn_proxy/common/types"
)

// This file contains all the common functions that's shared across loca/ldap APIs.

// deletePrincipal helper function to delete user.principal/group.principal; called from `DeleteLocalUser`/`DeleteLDAPMapping`.
// params:
// principal: reference of the principal object to be deleted from the data store
//  stateDrv: data store driver object
// return values:
//  error: custom error with error from `ClearState(...)`
func deletePrincipal(principal *types.Principal, stateDrv types.StateDriver) error {
	if err := stateDrv.ClearState(GetPath(RootPrincipals, principal.UUID)); err != nil {
		return fmt.Errorf("Failed to clear principal %#v from store %#v", principal, err)
	}

	return nil
}

// addPrincipal helper function to insert user.principal/group.principal; called from `AddLocalUser`/`AddLDAPMapping`.
// params:
//  principal: reference of the principal object to be inserted into the data store
//  stateDrv: data store driver object
// retutn values:
//  error: any relevant custom errors or as returned by consecutive calls
func addPrincipal(principal *types.Principal, stateDrv types.StateDriver) error {
	_, err := stateDrv.Read(GetPath(RootPrincipals, principal.UUID))

	switch err {
	case nil:
		return fmt.Errorf("%s: %q", ccnerrors.ErrKeyExists, principal.UUID)
	case ccnerrors.ErrKeyNotFound:
		val, err := json.Marshal(principal)
		if err != nil {
			return fmt.Errorf("Failed to marshal principal %#v, %#v", principal, err)
		}

		if err := stateDrv.Write(GetPath(RootPrincipals, principal.UUID), val); err != nil {
			return fmt.Errorf("Failed to write local user principal to data store %#v", err)
		}

		return nil
	default:
		return err
	}
}
