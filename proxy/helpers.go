package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	log "github.com/Sirupsen/logrus"
	uuid "github.com/satori/go.uuid"

	"github.com/contiv/ccn_proxy/auth"
	"github.com/contiv/ccn_proxy/common"
	ccnerrors "github.com/contiv/ccn_proxy/common/errors"
	"github.com/contiv/ccn_proxy/common/types"
	"github.com/contiv/ccn_proxy/usermgmt"
)

// getLdapMappingsHelper helper function to get mapping information of all LDAP groups.
// return values:
//  int: http status code
//  []byte: http response message; this goes along with status code
//          this could be an error message or JSON response based on the execution flow
func getLdapMappingsHelper() (int, []byte) {
	mappings, err := usermgmt.GetLdapMappings()
	if err != nil {
		return http.StatusInternalServerError, []byte(err.Error())
	}

	lms := []ldapMapping{}
	for _, mapping := range mappings {
		lm := ldapMapping{
			GroupName: mapping.GroupName,
			Role:      mapping.Principal.Role.String(),
		}
		lms = append(lms, lm)
	}

	jData, err := json.Marshal(lms)
	if err != nil {
		return http.StatusInternalServerError, []byte(err.Error())
	}

	return http.StatusOK, jData
}

// getLdapMappingHelper helper function to get mapping details of the given group name.
// params:
//  ldapGroupName: of the group whose mapping needs to be fetched
// return values:
//  int: http status code
//  []byte: http response message; this goes along with status code
//          this could be an error message or JSON response based on the execution flow
func getLdapMappingHelper(ldapGroupName string) (int, []byte) {
	if common.IsEmpty(ldapGroupName) {
		return http.StatusBadRequest, []byte("Empty group name")
	}

	mapping, err := usermgmt.GetLdapMapping(ldapGroupName)

	switch err {
	case nil:
		lm := ldapMapping{
			GroupName: mapping.GroupName,
			Role:      mapping.Principal.Role.String(),
		}

		jData, err := json.Marshal(lm)
		if err != nil {
			return http.StatusInternalServerError, []byte(err.Error())
		}

		return http.StatusOK, jData
	case ccnerrors.ErrKeyNotFound:
		return http.StatusNotFound, nil
	default:
		return http.StatusInternalServerError, []byte(err.Error())
	}
}

// updateLdapMappingInfo helper function for `updateLdapMappingHelper`
// params:
//  updateReq: *ldapMapping update request object
//  actual: existing *types.LdapRoleMapping in the data store;
//          new mapping object is created from actual + updateReq and added to the data store
// return values:
//  int: http status code
//  []byte: http response message; this goes along with status code
//          this could be an error message or JSON response based on the execution flow
func updateLdapMappingInfo(updateReq *ldapMapping, actual *types.LdapRoleMapping) (int, []byte) {
	updateMappingObj := &types.LdapRoleMapping{
		PrincipalID: actual.PrincipalID,
		GroupName:   actual.GroupName,
		Principal: types.Principal{
			UUID: actual.Principal.UUID,
		},
	}

	updateRequired := false
	if !common.IsEmpty(updateReq.Role) {
		role, err := types.Role(updateReq.Role)
		if err != nil {
			return http.StatusInternalServerError, []byte(fmt.Sprintf("Invalid role %q", role))
		}

		updateMappingObj.Principal.Role = role
		updateRequired = true
	}

	// default mapping response
	lm := ldapMapping{
		GroupName: actual.GroupName,
		Role:      actual.Principal.Role.String(),
	}

	// nothing needs to be updated; return here and save one data store operation, Yay!
	if !updateRequired {
		jData, err := json.Marshal(lm)
		if err != nil {
			return http.StatusInternalServerError, []byte(err.Error())
		}

		return http.StatusOK, jData
	}

	err := usermgmt.UpdateLdapMapping(actual.GroupName, updateMappingObj)
	switch err {
	case nil:
		// only the role is updated; nothing else in `lm` needs to be updated
		lm.Role = updateMappingObj.Principal.Role.String()

		jData, err := json.Marshal(lm)
		if err != nil {
			return http.StatusInternalServerError, []byte(err.Error())
		}

		return http.StatusOK, jData
	case ccnerrors.ErrKeyNotFound: // from DeleteLdapMapping()
		return http.StatusNotFound, nil
	default:
		return http.StatusInternalServerError, []byte(err.Error())
	}
}

// updateLdapMappingHelper helper function to update the existing LDAP mapping information.
// params:
//  ldapGroupName: of the group name to be updated
//  ldapMappingUpdateReq: *ldapMapping update request object
// return values:
//  int: http status code
//  []byte: http response message; this goes along with status code
//          this could be an error message or JSON response based on the execution flow
func updateLdapMappingHelper(ldapGroupName string, ldapMappingUpdateReq *ldapMapping) (int, []byte) {
	if common.IsEmpty(ldapGroupName) {
		return http.StatusBadRequest, []byte("Empty group name")
	}

	mapping, err := usermgmt.GetLdapMapping(ldapGroupName)
	switch err {
	case nil:
		return updateLdapMappingInfo(ldapMappingUpdateReq, mapping)
	case ccnerrors.ErrKeyNotFound:
		return http.StatusNotFound, nil
	default:
		return http.StatusInternalServerError, []byte(err.Error())
	}
}

// deleteLdapMappingHelper helper function to delete ldap-role mapping for the given group name.
// params:
//  ldapGroupName: of the group to be deleted from the store; ideally the mapping that gets deleted
// return values:
//  int: http status code
//  []byte: http response message; this goes along with status code
//          this could be an error message or JSON response based on the execution flow
func deleteLdapMappingHelper(ldapGroupName string) (int, []byte) {
	if common.IsEmpty(ldapGroupName) {
		return http.StatusBadRequest, []byte("Empty group name")
	}

	err := usermgmt.DeleteLdapMapping(ldapGroupName)
	switch err {
	case nil:
		return http.StatusNoContent, nil
	case ccnerrors.ErrKeyNotFound:
		return http.StatusNotFound, nil
	default:
		return http.StatusInternalServerError, []byte(err.Error())
	}
}

// addLdapMappingHelper helper function to add the given ldap-role mapping to the data store.
// params:
//  ldapMappingReq: ldapMapping request object; based on which types.LdapRoleMapping is created
// return values:
//  int: http status code
//  []byte: http response message; this goes along with status code
//          this could be an error message or JSON response based on the execution flow
func addLdapMappingHelper(ldapMappingReq *ldapMapping) (int, []byte) {
	if common.IsEmpty(ldapMappingReq.GroupName) {
		return http.StatusBadRequest, []byte("Empty group name")
	}

	role, err := types.Role(ldapMappingReq.Role)
	if err != nil {
		return http.StatusBadRequest, []byte(fmt.Sprintf("Invalid role %q", ldapMappingReq.Role))
	}

	pID := uuid.NewV4().String()
	mapping := types.LdapRoleMapping{
		GroupName: ldapMappingReq.GroupName,
		Principal: types.Principal{
			UUID: pID,
			Role: role,
		},
		PrincipalID: pID,
	}

	err = usermgmt.AddLdapMapping(&mapping)
	switch err {
	case nil:
		lm := ldapMapping{
			GroupName: mapping.GroupName,
			Role:      mapping.Principal.Role.String(),
		}

		jData, err := json.Marshal(lm)
		if err != nil {
			return http.StatusInternalServerError, []byte(err.Error())
		}

		return http.StatusCreated, jData
	case ccnerrors.ErrKeyExists:
		return http.StatusBadRequest, []byte(fmt.Sprintf("Mapping for group %q exists already", ldapMappingReq.GroupName))
	default:
		return http.StatusInternalServerError, []byte(err.Error())
	}

}

// getLocalUserHelper helper function to get the details of given username.
// params:
//  username: of the user to fetch details from the data store
// return values:
//  int: http status code
//  []byte: http response message; this goes along with status code
//          on successful fetch from data store, it contains `localUser` object
func getLocalUserHelper(username string) (int, []byte) {
	user, err := usermgmt.GetLocalUser(username)

	switch err {
	case nil:
		lu := localUser{
			Username: user.LocalUser.Username,
			Disable:  user.LocalUser.Disable,
			Role:     user.Principal.Role.String(),
		}

		jData, err := json.Marshal(lu)
		if err != nil {
			return http.StatusInternalServerError, []byte(err.Error())
		}

		return http.StatusOK, jData
	case ccnerrors.ErrKeyNotFound:
		return http.StatusNotFound, nil
	default:
		return http.StatusInternalServerError, []byte(err.Error())
	}

}

// getLocalUsersHelper helper function to get the list of local users.
// return values:
//  int: http status code
//  []byte: http response message; this goes along with status code
//          on successful fetch from data store, it contains the list of localuser objects
func getLocalUsersHelper() (int, []byte) {
	users, err := usermgmt.GetLocalUsers()
	if err != nil {
		return http.StatusInternalServerError, []byte(err.Error())
	}

	localUsers := []localUser{}
	for _, user := range users {
		lu := localUser{
			Username: user.LocalUser.Username,
			Disable:  user.LocalUser.Disable,
			Role:     user.Principal.Role.String(),
		}
		localUsers = append(localUsers, lu)
	}

	jData, err := json.Marshal(localUsers)
	if err != nil {
		return http.StatusInternalServerError, []byte(err.Error())
	}

	return http.StatusOK, jData
}

// updateLocalUserInfo helper function for updateLocalUserHelper.
// params:
//  username: of the user to be updated
//  updateReq: *localUserCreateRequest contains the fields to be updated
//  actual: *types.InternalLocalUser representation of `username` fetched from the data store
// return values:
//  int: http status code
//  []byte: http response message; this goes along with status code
func updateLocalUserInfo(username string, updateReq *localUserCreateRequest, actual *types.InternalLocalUser) (int, []byte) {
	updatedUserObj := &types.InternalLocalUser{
		PrincipalID: actual.PrincipalID,
		Principal: types.Principal{
			UUID: actual.PrincipalID,
		},
		LocalUser: types.LocalUser{
			// `actual.LocalUser.Username` will be the same as `username`
			Username: actual.LocalUser.Username,
		},
	}

	// Update `role`
	if !common.IsEmpty(updateReq.Role) {
		role, err := types.Role(updateReq.Role)
		if err != nil {
			return http.StatusInternalServerError, []byte(fmt.Sprintf("Failed to map role %q", updateReq.Role))
		}
		updatedUserObj.Principal.Role = role
	}

	// Update `disable`
	if actual.Disable != updateReq.Disable {
		updatedUserObj.LocalUser.Disable = updateReq.Disable
	}

	// Update `password`
	if !common.IsEmpty(updateReq.Password) {
		var err error
		updatedUserObj.PasswordHash, err = common.GenPasswordHash(updateReq.Password)
		if err != nil {
			return http.StatusInternalServerError, []byte(fmt.Sprintf("Failed to create password hash for user %q", username))
		}
	}

	err := usermgmt.UpdateLocalUser(username, updatedUserObj)
	switch err {
	case nil:
		lu := localUser{
			Username: updatedUserObj.LocalUser.Username,
			Disable:  updatedUserObj.LocalUser.Disable,
			Role:     updatedUserObj.Principal.Role.String(),
		}

		jData, err := json.Marshal(lu)
		if err != nil {
			return http.StatusInternalServerError, []byte(err.Error())
		}

		return http.StatusOK, jData
	case ccnerrors.ErrKeyNotFound: // from DeleteLocalUser()
		return http.StatusNotFound, nil
	case ccnerrors.ErrIllegalOperation:
		return http.StatusBadRequest, []byte(fmt.Sprintf("Cannot update built-in user %q", username))
	default:
		return http.StatusInternalServerError, []byte(err.Error())
	}

}

// updateLocalUserHelper helper function to update the existing user details in the data store.
// params:
// username: of the user to be updated
// userUpdateReq: *localUserCreateRequest contains the fields to be updated
// return values:
//  int: http status code
//  []byte: http response message; this goes along with status code
func updateLocalUserHelper(username string, userUpdateReq *localUserCreateRequest) (int, []byte) {
	if common.IsEmpty(username) {
		return http.StatusBadRequest, []byte("Empty username")
	}

	localUser, err := usermgmt.GetLocalUser(username)
	switch err {
	case nil:
		return updateLocalUserInfo(username, userUpdateReq, localUser)
	case ccnerrors.ErrKeyNotFound:
		return http.StatusNotFound, nil
	default:
		return http.StatusInternalServerError, []byte(err.Error())
	}

}

// deleteLocalUserHelper helper function to delete given user from the data store.
// params:
//  username: of the user to be deleted from store
// return values:
//  int: http status code
//  []byte: http response message; this goes along with status code
func deleteLocalUserHelper(username string) (int, []byte) {
	if common.IsEmpty(username) {
		return http.StatusBadRequest, []byte("Empty username")
	}

	err := usermgmt.DeleteLocalUser(username)
	switch err {
	case nil:
		return http.StatusNoContent, nil
	case ccnerrors.ErrKeyNotFound:
		return http.StatusNotFound, nil
	case ccnerrors.ErrIllegalOperation:
		return http.StatusBadRequest, []byte(fmt.Sprintf("Cannot delete built-in user %q", username))
	default:
		return http.StatusInternalServerError, []byte(err.Error())
	}
}

// addLocalUserHelper helper function to add given user to the data store.
// params:
//  userCreateReq: localUserCreateRequest object; based on which types.InternalLocalUser is created
// return values:
//  int: http status code
//  []byte: http response message; this goes along with status code
func addLocalUserHelper(userCreateReq *localUserCreateRequest) (int, []byte) {
	if common.IsEmpty(userCreateReq.Username) || common.IsEmpty(userCreateReq.Password) {
		return http.StatusBadRequest, []byte("username/password is empty")
	}

	role, err := types.Role(userCreateReq.Role)
	if err != nil {
		return http.StatusBadRequest, []byte(fmt.Sprintf("Invalid role %q", userCreateReq.Role))
	}

	pID := uuid.NewV4().String()
	user := types.InternalLocalUser{
		LocalUser: types.LocalUser{
			Username: userCreateReq.Username,
			Disable:  userCreateReq.Disable,
		},
		Principal: types.Principal{
			UUID: pID,
			Role: role,
		},
		PrincipalID: pID,
	}

	user.PasswordHash, err = common.GenPasswordHash(userCreateReq.Password)
	if err != nil {
		return http.StatusInternalServerError, []byte(fmt.Sprintf("Failed to create password hash for user %q", userCreateReq.Username))
	}

	err = usermgmt.AddLocalUser(&user)
	switch err {
	case nil:
		lu := localUser{
			Username: user.LocalUser.Username,
			Disable:  user.LocalUser.Disable,
			Role:     user.Principal.Role.String(),
		}

		jData, err := json.Marshal(lu)
		if err != nil {
			return http.StatusInternalServerError, []byte(err.Error())
		}

		return http.StatusCreated, jData
	case ccnerrors.ErrKeyExists:
		return http.StatusBadRequest, []byte("user exists already")
	default:
		return http.StatusInternalServerError, []byte(err.Error())
	}
}

// isTokenValid checks if the given token string is valid(correctness, expiry, etc.) and writes
// the respective http response based on the validation.
// params:
//  tokenStr: token string obtained from the http request
//  w: http response writer
// return values:
//  bool: boolean representing the token validatity
//  *auth.Token: token object parsed from the tokenStr
func isTokenValid(tokenStr string, w http.ResponseWriter) (bool, *auth.Token) {
	if common.IsEmpty(tokenStr) {
		authError(w, http.StatusUnauthorized, "Empty auth token")
		return false, nil
	}

	// NOTE: our current implementation focuses on just two local users admin(superuser) and ops(only network operations).
	// this is mainly to provide some basic difference between two users
	// this needs to be fine-grained once we have the backend and capabilities defined

	token, err := auth.ParseToken(tokenStr)
	if err != nil {
		authError(w, http.StatusBadRequest, "Bad token")
		return false, nil
	}

	// TODO: Check if the user is still active (~disable/~delete)
	return true, token
}

//
// processStatusCodes processes the given statusCode and
// writes the respective http response using the given writer.
// params:
//  statusCode: integer representing the http status code
//  resp: response to be written along with statusCode
//  w: http response writer
//
func processStatusCodes(statusCode int, resp []byte, w http.ResponseWriter) {
	common.SetJSONContentType(w)
	switch statusCode {
	case http.StatusCreated, http.StatusOK:
		w.WriteHeader(statusCode)
		w.Write(resp)
	case http.StatusNotFound, http.StatusNoContent:
		w.WriteHeader(statusCode)
	default: //InternalServerError, BadRequest, etc..
		respStr := string(resp)
		log.Println(respStr)
		w.WriteHeader(statusCode)
		writeJSONResponse(w, errorResponse{Error: respStr})
	}
}

//
// getTokenFromHeader retrieves the token from an HTTP request
// header
//
// Parameters:
//   req: HTTP request from whose header the authz token needs to be
//        retrieved
//
// Return values:
//   string: token as a string
//   err:    ccnerrors.ErrParsingToken
//           nil if token is retrieved successfully
//
func getTokenFromHeader(req *http.Request) (string, error) {

	defer common.Untrace(common.Trace())
	var err error
	tokenStr := req.Header.Get("X-Auth-Token")
	if common.IsEmpty(tokenStr) {
		err = ccnerrors.ErrParsingToken
	}
	return tokenStr, err
}

// writeJSONResponse writes the given data in JSON format.
func writeJSONResponse(w http.ResponseWriter, data interface{}) {
	jData, err := json.Marshal(data)
	if err != nil {
		log.Fatalln(err)
		return
	}

	w.Write(jData)
}

//
// convertAuthz converts the Authorization object into reply struct
// for Add tenant authorization and Get tenant authorization API
// calls
//
// Parameter:
//   authz: Authorization object
//
// Return values:
//   GetAuthorizationReply: Reply struct for add and get tenant
//                          authorization APIs
//
func convertAuthz(authz types.Authorization) GetAuthorizationReply {
	getAuthzReply := GetAuthorizationReply{
		AuthzUUID:     authz.UUID,
		PrincipalName: authz.PrincipalName,
		TenantName:    strings.TrimPrefix(authz.ClaimKey, types.TenantClaimKey),
		Local:         authz.Local,
		Role:          authz.ClaimValue,
	}
	return getAuthzReply
}
