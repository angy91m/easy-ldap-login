# easy-ldap-login

easy-ldap-login is a wrapper of [ldapjs](https://www.npmjs.com/package/ldapjs) package that allows you to easily authenticate users on LDAP server and check if they are in a specific group.

## Installation

```bash
npm i easy-ldap-login
```

## Usage

```javascript
const LDAPLogin = require( 'easy-ldap-login' );
const ldapLogin = new LDAPLogin( 'ldap://myldap01.server.com', 'dc=domain,dc=com', { searchGroups: 'team_marketing' } );
ldapLogin.auth( 'userName', 'password' )
.then( () => console.log( 'User authenticated' ) )
.catch( () => console.log( 'Wrong credentials' ) );
```

## Methods

### `LDAPLogin.constructor`
```javascript
new LDAPLogin( serverUrls: String | Array, dcString: String [, options: Object = {} ] );
```

#### Parameters

* `serverUrls` Required - URL of the ldap server as `String` or an `Array` of URL Strings for round-robin
* `dcString` Required - `String` that identifies Domain Component
* `options` Optional - Module options as an `Object` with some properties:
  * `usersOu` Optional - `String` that identifies Organization Unit base for Users (Default: `'ou=users'`)
  * `userAttribute` Optional - `String` that identifies ID attribute for Users (Default: `'uid'`)
  * `groupsOu` Optional - `String` that identifies Organization Unit base for Groups (Default: `'ou=groups'`)
  * `groupMemberAttribute` Optional - `String` that identifies Group attribute to use for searching its members (Default: `'member'`)
  * `searchGroups` Optional - It can be one of these:
    * `String` that identifies Common Name of Group that User must have
    * `Object` with properties:
      * `cn` Required - `String` that identifies Common Name of the Group that User must have
      * `ou` Required - `String` that identifies Organization Unit base string of the Group
      * `userAttribute` Optional - `String` that identifies ID attribute for Users in the Group
      * `groupMemberAttribute` Optional - `String` that identifies Group attribute to use for searching its members
    * `Array` of the previous data for multiple groups

#### Return

An instance of `LDAPLogin`

### `LDAPLogin.auth`
```javascript
ldapLogin.auth( userName: String, password: String [, options: Object = {} ] );
```

#### Parameters

* `userName` Required - User's userName
* `password` Required - User's password
* `options` Optional - Module options as an `Object` with some properties:
  * `serverUrls` Optional - URL of the ldap server as `String` or an `Array` of URL Strings for multiple attempts
  * `usersOu` Optional - `String` that identifies Organization Unit base for Users (Default: `'ou=users'`)
  * `userAttribute` Optional - `String` that identifies ID attribute for Users (Default: `'uid'`)
  * `groupsOu` Optional - `String` that identifies Organization Unit base for Groups (Default: `'ou=groups'`)
  * `groupMemberAttribute` Optional - `String` that identifies Group attribute to use for searching its members (Default: `'member'`)
  * `searchGroups` Optional - It can be one of these:
    * `String` that identifies Common Name of Group that User must have
    * `Object` with properties:
      * `cn` Required - `String` that identifies Common Name of the Group that User must have
      * `ou` Required - `String` that identifies Organization Unit base string of the Group
      * `userAttribute` Optional - `String` that identifies ID attribute for Users in the Group
      * `groupMemberAttribute` Optional - `String` that identifies Group attribute to use for searching its members
    * `Array` of the previous data for multiple groups

#### Return

A promise that resolve if user correctly logged or reject error