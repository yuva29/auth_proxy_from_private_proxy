package usermgmt

import (
	"encoding/json"
	"fmt"

	log "github.com/Sirupsen/logrus"
	ccnerrors "github.com/contiv/ccn_proxy/common/errors"
	"github.com/contiv/ccn_proxy/common/types"
	"github.com/contiv/ccn_proxy/state"
)

// This file contains all LDAP->Role mapping APIs.

// getLdapMapping helper function that looks up mapping entry in `ldap_mappings` using the given group name.
// params:
//  ldapGroupName: of the group whose mapping needs to be fetched
//  stateDrv: data store driver object
// return values:
//  *types.LdapRoleMapping: reference to the internal representation of ldap-role mapping object
//  error: as returned by consecutive function calls or any relevant custom errors
func getLdapMapping(ldapGroupName string, stateDrv types.StateDriver) (*types.LdapRoleMapping, error) {
	rawData, err := stateDrv.Read(GetPath(RootLdapMappings, ldapGroupName))
	if err != nil {
		if err == ccnerrors.ErrKeyNotFound {
			return nil, err
		}

		return nil, fmt.Errorf("Failed to read LDAP mapping  for group %q from data store: %#v", ldapGroupName, err)
	}

	var ldapMapping types.LdapRoleMapping
	if err := json.Unmarshal(rawData, &ldapMapping); err != nil {
		return nil, fmt.Errorf("Failed to unmarshal LDAP mapping for group %q: %#v", ldapGroupName, err)
	}

	return &ldapMapping, nil
}

// AddLdapMapping adds a new entry in `ccn_proxy/ldap_mappings`.
// It also adds a corresponding principal in `/ccn_proxy/principals`
// params:
//  ldapMapping: reference to internal representation (ldap-role mapping + principal)
//               object to be added to the data store
//               NOTE: there is always one-to-one mapping of ldap group to principal
// return values:
//  error: ccnerrors.ErrKeyExists if the group already exists or any relevant error(+custom) from data store
func AddLdapMapping(ldapMapping *types.LdapRoleMapping) error {
	stateDrv, err := state.GetStateDriver()
	if err != nil {
		return err
	}

	_, err = getLdapMapping(ldapMapping.GroupName, stateDrv)
	switch err {
	case nil:
		return ccnerrors.ErrKeyExists
	case ccnerrors.ErrKeyNotFound:
		val, err := json.Marshal(ldapMapping)
		if err != nil {
			return fmt.Errorf("Failed to marshal LDAP group mapping %#v: %#v", ldapMapping, err)
		}

		if err := addPrincipal(&ldapMapping.Principal, stateDrv); err != nil {
			return err
		}

		// if `Write` fails, data store may become inconsistent based on `deletePrincipal`'s execution
		if err := stateDrv.Write(GetPath(RootLdapMappings, ldapMapping.GroupName), val); err != nil {
			// cleanup; to ensure group.principal is not left behind in the data store
			// if `deletePrincipal` fails data store will be in inconsistent state
			deletePrincipal(&ldapMapping.Principal, stateDrv)
			return fmt.Errorf("Failed to write LDAP group mapping info. to data store: %#v", err)
		}

		return nil
	default:
		return err
	}
}

// DeleteLdapMapping deletes a mapping entry from `/ccn_proxy/ldap_mappings` for the given group name.
// This also deletes the respective principal from `ccn_proxy/principals`
// params:
//  ldapGroupName: of the group whose mapping needs to be deleted
// return values:
//  error: as returned from any of `common.GetStateDriver()`, `getLdapMapping` and `deletePrincipal`
//         or any relevant custom error
func DeleteLdapMapping(ldapGroupName string) error {
	stateDrv, err := state.GetStateDriver()
	if err != nil {
		return err
	}

	ldapMapping, err := getLdapMapping(ldapGroupName, stateDrv)
	if err != nil {
		return err
	}

	if err := deletePrincipal(&ldapMapping.Principal, stateDrv); err != nil {
		return err
	}

	// if `ClearState` fails, data store may become inconsistent based on `addPrincipal`'s execution
	if err := stateDrv.ClearState(GetPath(RootLdapMappings, ldapGroupName)); err != nil {
		//cleanup; there is always a principal associated with group (1-1 mapping)
		// if `addPrincipal` fails data store will be in inconsistent state
		addPrincipal(&ldapMapping.Principal, stateDrv)
		return fmt.Errorf("Failed to delete group %q from store: %#v", ldapGroupName, err)
	}

	return nil
}

// UpdateLdapMapping updates the mapping entry for a given group name in `/ccn_proxy/ldap_mappings`.
// params:
//  ldapGroupName: of the group whose mapping needs to be updated
//  ldapMapping: reference to internal representation (ldap-role mapping + principal)
//               object to be updated to the data store
// return values:
//  error: as returned by `DeleteLdapMapping`/`AddLdapMapping`
//         or any relevant custom error
func UpdateLdapMapping(ldapGroupName string, ldapMapping *types.LdapRoleMapping) error {
	err := DeleteLdapMapping(ldapGroupName)
	switch err {
	case nil:
		return AddLdapMapping(ldapMapping)
	case ccnerrors.ErrKeyNotFound:
		return err
	default:
		// this should never be leaked to the user
		log.Debugf("Failed to delete ldap mapping for the group %q as part of update process: %#v", ldapGroupName, err)
		return fmt.Errorf("Couldn't update ldap mapping information for group %q", ldapGroupName)
	}

}

// GetLdapMapping returns a mapping entry from `/ccn_proxy/ldap_mappings` for the given group name
// params:
//  ldapGroupName: of the group whose mapping needs to be fetched
// return values:
//  *types.LdapRoleMapping: reference to internal representation (ldap-role mapping + principal) object
//  error: as returned by consecutive function calls
func GetLdapMapping(ldapGroupName string) (*types.LdapRoleMapping, error) {
	stateDrv, err := state.GetStateDriver()
	if err != nil {
		return nil, err
	}

	return getLdapMapping(ldapGroupName, stateDrv)
}

// GetLdapMappings returns all the mapping entry from `/ccn_proxy/ldap_mappings`
// return values:
//  []*types.LdapRoleMapping: list of LDAP role mappings
//  error: as returned by consecutive function calls
//         or any relevant custom error
func GetLdapMappings() ([]*types.LdapRoleMapping, error) {
	stateDrv, err := state.GetStateDriver()
	if err != nil {
		return nil, err
	}

	mappings := []*types.LdapRoleMapping{}

	rawData, err := stateDrv.ReadAll(GetPath(RootLdapMappings))
	if err != nil {
		//NOTE: DELETE deletes the entire path `/ccn_proxy/lap_mappings` if there is no child in the path.
		//      So, it can very well return `ccnerrors.ErrKeyNotFound` if no mapping exists
		if err == ccnerrors.ErrKeyNotFound {
			return mappings, nil
		}

		log.Debugf("Couldn't fetch LDAP mappings : %#v", err)
		return nil, fmt.Errorf("Couldn't fetch LDAP mappings from data store")
	}

	for _, data := range rawData {
		ldapMapping := &types.LdapRoleMapping{}
		if err := json.Unmarshal(data, ldapMapping); err != nil {
			return nil, err
		}

		mappings = append(mappings, ldapMapping)
	}

	return mappings, nil
}
