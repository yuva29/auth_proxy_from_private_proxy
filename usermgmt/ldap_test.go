package usermgmt

import (
	ccnerrors "github.com/contiv/ccn_proxy/common/errors"
	"github.com/contiv/ccn_proxy/common/types"
	uuid "github.com/satori/go.uuid"
	. "gopkg.in/check.v1"
)

var (
	newMappings = []map[string]string{
		{"group_name": "aaa", "role": "admin"},
		{"group_name": "bbb", "role": "admin"},
		{"group_name": "ccc", "role": "ops"},
		{"group_name": "ddd", "role": "admin"},
	}

	nonExistingGroups = []string{"xxx", "yyy", "zzz"}
)

func (s *usermgmtSuite) TestAddLdapMapping(c *C) {
	// add new mappings
	for _, mapping := range newMappings {
		role, err := types.Role(mapping["role"])
		c.Assert(err, IsNil)
		c.Assert(role.String(), Equals, mapping["role"])

		pID := uuid.NewV4().String()
		m := &types.LdapRoleMapping{
			PrincipalID: pID,
			Principal: types.Principal{
				UUID: pID,
				Role: role,
			},
			GroupName: mapping["group_name"],
		}

		err = AddLdapMapping(m)
		c.Assert(err, IsNil)

		err = AddLdapMapping(m)
		c.Assert(err, Equals, ccnerrors.ErrKeyExists)
	}
}

func (s *usermgmtSuite) TestGetLdapMapping(c *C) {
	for _, mapping := range newMappings {
		lm, err := GetLdapMapping(mapping["group_name"])
		c.Assert(err, Equals, ccnerrors.ErrKeyNotFound)
		c.Assert(lm, IsNil)
	}

	s.TestAddLdapMapping(c)

	for _, mapping := range newMappings {
		lm, err := GetLdapMapping(mapping["group_name"])
		c.Assert(err, IsNil)
		c.Assert(lm, NotNil)
	}

	for _, groupName := range nonExistingGroups {
		mapping, err := GetLdapMapping(groupName)
		c.Assert(err, Equals, ccnerrors.ErrKeyNotFound)
		c.Assert(mapping, IsNil)
	}
}

func (s *usermgmtSuite) TestGetLdapMappings(c *C) {
	// test `ErrKeyNotFound`
	_, err := GetLdapMappings()
	c.Assert(err, Equals, ccnerrors.ErrKeyNotFound)

	s.TestAddLdapMapping(c)

	obtianedMappings := []map[string]string{}

	mappings, err := GetLdapMappings()
	c.Assert(err, IsNil)
	for _, mapping := range mappings {
		m := map[string]string{}
		m["group_name"] = mapping.GroupName
		m["role"] = mapping.Principal.Role.String()

		obtianedMappings = append(obtianedMappings, m)
	}

	c.Assert(obtianedMappings, DeepEquals, newMappings)

}
