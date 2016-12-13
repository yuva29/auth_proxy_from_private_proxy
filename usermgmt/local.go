package usermgmt

import (
	"encoding/json"
	"fmt"

	log "github.com/Sirupsen/logrus"
	"github.com/contiv/ccn_proxy/common"
	ccnerrors "github.com/contiv/ccn_proxy/common/errors"
	"github.com/contiv/ccn_proxy/common/types"
	"github.com/contiv/ccn_proxy/state"
)

// This file contains all local user management APIs.
// NOTE: Built-in users(admin, ops) cannot be changed/updated. it needs to be consumed in the way its defined in code.

// getLocalUser helper function that looks up a user entry in `/ccn_proxy/local_users` using username
// params:
//  username:string; name of the user to be fetched
// return values:
//  *types.InternalLocalUser: reference to the internal representation of the local user object
//  error: as returned by the consecutive calls or any relevant custom errors
func getLocalUser(username string, stateDrv types.StateDriver) (*types.LocalUser, error) {
	rawData, err := stateDrv.Read(GetPath(RootLocalUsers, username))
	if err != nil {
		if err == ccnerrors.ErrKeyNotFound {
			return nil, err
		}

		return nil, fmt.Errorf("Failed to read local user %q data from store: %#v", username, err)
	}

	var localUser types.LocalUser
	if err := json.Unmarshal(rawData, &localUser); err != nil {
		return nil, fmt.Errorf("Failed to unmarshal local user %q info %#v", username, err)
	}

	return &localUser, nil
}

// GetLocalUsers returns all defined local users.
// return values:
//  []types.InternalLocalUser: slice of local users
//  error: as returned by consecutive func calls
func GetLocalUsers() ([]*types.LocalUser, error) {
	stateDrv, err := state.GetStateDriver()
	if err != nil {
		return nil, err
	}

	users := []*types.LocalUser{}
	rawData, err := stateDrv.ReadAll(GetPath(RootLocalUsers))
	if err != nil {
		if err == ccnerrors.ErrKeyNotFound {
			return users, nil
		}

		return nil, fmt.Errorf("Couldn't fetch users from data store")
	}

	for _, data := range rawData {
		localUser := &types.LocalUser{}
		if err := json.Unmarshal(data, localUser); err != nil {
			return nil, err
		}

		users = append(users, localUser)
	}

	return users, nil
}

// GetLocalUser looks up a user entry in `/ccn_proxy/local_users` path.
// params:
//  username:string; name of the user to be fetched
// return values:
//  *types.LocalUser: reference to local user object fetched from data store
//  error: as returned by getLocalUser(..)
func GetLocalUser(username string) (*types.LocalUser, error) {
	stateDrv, err := state.GetStateDriver()
	if err != nil {
		return nil, err
	}

	return getLocalUser(username, stateDrv)
}

// UpdateLocalUser updates an existing entry in /ccn_proxy/local_users/<username>.
// params:
//  username: string; of the user that requires update
//  user: local user object to be updated in the data store
// return values:
//  error: as returned by AddLocalUser, DeleteLocalUser
func UpdateLocalUser(username string, user *types.LocalUser) error {
	err := DeleteLocalUser(username)
	switch err {
	case nil:
		if !common.IsEmpty(user.Password) {
			user.PasswordHash = []byte{}
		}

		return AddLocalUser(user)
	case ccnerrors.ErrKeyNotFound, ccnerrors.ErrIllegalOperation:
		return err
	default:
		// this should never be leaked to the user
		log.Debugf("Failed to delete user %q as part of update process %#v", username, err)
		return fmt.Errorf("Couldn't update user information: %q", username)
	}
}

// DeleteLocalUser removes a local user from `/ccn_proxy/local_users`
// Built-in admin and ops local users cannot be deleted.
// params:
//  username: string; user to be removed from the system
// return values:
//  error: ccnerrors.ErrIllegalOperation or any relevant error from the consecutive func calls
func DeleteLocalUser(username string) error {
	if username == types.Admin.String() || username == types.Ops.String() {
		// built-in users cannot be deleted
		return ccnerrors.ErrIllegalOperation
	}

	stateDrv, err := state.GetStateDriver()
	if err != nil {
		return err
	}

	_, err = getLocalUser(username, stateDrv)
	if err != nil {
		return err
	}

	if err := stateDrv.Clear(GetPath(RootLocalUsers, username)); err != nil {
		return fmt.Errorf("Failed to clear %q from store %#v", username, err)
	}

	return nil
}

// AddLocalUser adds a new user entry to /ccn_proxy/local_users/.
// params:
//  user: *types.LocalUser object that should be added to the data store
// return Values:
//  error: ccnerrors.ErrKeyExists if the user already exists or any relevant error from state driver
func AddLocalUser(user *types.LocalUser) error {
	stateDrv, err := state.GetStateDriver()
	if err != nil {
		return err
	}

	key := GetPath(RootLocalUsers, user.Username)

	_, err = stateDrv.Read(key)

	switch err {
	case nil:
		return ccnerrors.ErrKeyExists
	case ccnerrors.ErrKeyNotFound:
		// `AddLocalUser` request from update carries hash in `user.PasswordHash`
		if common.IsEmpty(string(user.PasswordHash)) {
			user.PasswordHash, err = common.GenPasswordHash(user.Password)

			if err != nil {
				log.Debugf("Failed to create password hash for user %q: %#v", user.Username, err)
				return err
			}
		}

		// raw password will never be stored in the store
		user.Password = ""

		val, err := json.Marshal(user)
		if err != nil {
			return fmt.Errorf("Failed to marshal user %#v: %#v", user, err)
		}

		if err := stateDrv.Write(key, val); err != nil {
			return fmt.Errorf("Failed to write local user info. to data store %#v", err)
		}

		return nil
	default:
		return err
	}
}

// AddDefaultUsers adds pre-defined  users(admin,ops) to the system.
// Default users cannot be changed(update/delete) anytime.
func AddDefaultUsers() error {
	for _, userR := range []types.RoleType{types.Admin, types.Ops} {
		log.Printf("Adding local user %q to the system", userR.String())

		localUser := types.LocalUser{
			Username: userR.String(),
			// default user accounts are `enabled` always; it cannot be disabled
			Disable:  false,
			Password: userR.String(),
		}

		err := AddLocalUser(&localUser)
		if err == nil || err == ccnerrors.ErrKeyExists {
			continue
		}

		// TODO: add default authorization as well

		return err
	}

	return nil
}
