const ldap = require( 'ldapjs' );
const EventEmitter = require( 'node:events' );
const urlRegex = /^ldaps?:\/\/[-a-zA-Z0-9%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}(:((6553[0-5])|(655[0-2][0-9])|(65[0-4][0-9]{2})|(6[0-4][0-9]{3})|([1-5][0-9]{4})|([0-5]{0,5})|([0-9]{1,4})))?$/
const portRegex = /:((6553[0-5])|(655[0-2][0-9])|(65[0-4][0-9]{2})|(6[0-4][0-9]{3})|([1-5][0-9]{4})|([0-5]{0,5})|([0-9]{1,4}))$/

const validateUrl = url => {
    if ( url.match( urlRegex ) ) {
        if ( !url.match( portRegex ) ) {
            if ( url.startsWith( 'ldaps' ) ) {
                url += ':636';
            } else {
                url += ':389';
            }
        }
        return url;
    } else {
        return false;
    }
};

const validateUrls = urls => {
    if ( typeof urls === 'string' ) {
        urls = [urls];
    }
    return urls.map( validateUrl );
}
class LDAPLogin {
    constructor( serverUrls, dcString, options = {} ) {
        if ( !serverUrls.length ) throw new Error( 'serverUrls must be defined' );
        serverUrls = validateUrls( serverUrls );
        if ( !serverUrls.every( url => url ) ) throw new Error( 'Invalid serverUrls' );
        if ( !dcString ) throw new Error( 'dcString must be defined' );
        const defaultOpts = {
            usersOu: 'ou=users',
            userAttribute: 'uid',
            groupsOu: 'ou=groups',
            groupMemberAttribute: 'member',
            searchGroups: undefined,
            ...options
        };
        this.serverUrls = serverUrls;
        this.dcString = dcString;
        this.usersOu = defaultOpts.usersOu;
        this.userAttribute = defaultOpts.userAttribute;
        this.groupsOu = defaultOpts.groupsOu;
        this.groupMemberAttribute = defaultOpts.groupMemberAttribute;
        this.searchGroups = defaultOpts.searchGroups;
        this.robin = 0;
        this.busyServers = [];
    }
    async waitForFree( url ) {
        while ( this.busyServers.includes( url ) ) {
            await new Promise( r => setTimeout( r, 0 ) );
        }
        return;
    }
    connect( serverUrls ) {
        return new Promise( ( resolve, reject ) => {
            if ( typeof serverUrls === 'string' ) serverUrls = [serverUrls];
            const thisRobin = serverUrls === this.serverUrls;
            const errors = [];
            const emitter = new EventEmitter();
            let i = 0;
            emitter.on( 'next', () => {
                if ( i === serverUrls.length ) {
                    return emitter.emit( 'close' );
                } 
                let index = i;
                if ( thisRobin ) {
                    index = this.robin++;
                    if ( this.robin === serverUrls.length ) this.robin = 0;
                }
                this.waitForFree( serverUrls[index] )
                .then( () => {
                    const client = ldap.createClient( { url: serverUrls[index] } );
                    client.on( 'error', err => {
                        errors.push( err.message );
                        client.unbind();
                        i++;
                        return emitter.emit( 'next' );
                    } );
                    client.on( 'connect', () => {
                        client.srvUrl = serverUrls[index];
                        this.busyServers.push( serverUrls[index] );
                        emitter.removeAllListeners();
                        client.on( 'end', () => {
                            this.busyServers.splice( this.busyServers.findIndex( ( url ) => client.srvUrl === url ), 1 );
                        } );
                        return resolve( client );
                    } );
                } );
            } );
            emitter.on( 'close', () => {
                emitter.removeAllListeners();
                reject( errors );
            } );
            emitter.emit( 'next' );
        } );
    }
    search( client, groupStr, groupMemberAttribute, userName, userAttribute ) {
        return new Promise( ( resolve, reject ) => {
            client.search( groupStr, { attributes: [groupMemberAttribute] }, ( err, res ) => {
                if ( err ) {
                    reject( err );
                    return;
                }
                res.on( 'error', ( err ) => {
                    reject( err );
                } );
                res.on( 'searchEntry', entry => {
                    const users = entry.object.member.map( user => {
                        user = user.slice( user.indexOf( userAttribute ) + userAttribute.length + 1, user.indexOf( ',', user.indexOf( userAttribute ) ) );
                        return user;
                    } );
                    if ( !users.includes( userName ) ) {
                        reject( new Error( 'User not in cn' ) );
                    } else {
                        resolve( true );
                    }
                } );
            } );
        } );
    }
    auth( userName, password, options = {} ) {
        if ( typeof options.serverUrls !== 'undefined' ) {
            options.serverUrls = validateUrls( options.serverUrls );
            if ( !options.serverUrls.every( url => url ) ) throw new Error( 'Invalid serverUrls' );
        }
        const defaultOpts = {
            serverUrls: this.serverUrls,
            dcString: this.dcString,
            usersOu: this.usersOu,
            userAttribute: this.userAttribute,
            groupsOu: this.groupsOu,
            groupMemberAttribute: this.groupMemberAttribute,
            searchGroups: this.searchGroups,
            ...options
        };
        let { serverUrls, dcString, usersOu, userAttribute, groupsOu, groupMemberAttribute, searchGroups } = defaultOpts;
        return new Promise( ( resolve, reject ) => {
            this.connect( serverUrls )
            .then( client => {
                client.bind( userAttribute + '=' + userName +','+ usersOu + ',' + dcString, password, err => {
                    if ( err ) {
                        client.unbind();
                        return reject( err );
                    }
                    if ( !searchGroups ) {
                        client.unbind();
                        return resolve();
                    }
                    if ( typeof searchGroups === 'string' ) searchGroups = [searchGroups];
                    const promises = [];
                    searchGroups.forEach( gr => {
                        if ( typeof gr === 'string' ) {
                            promises.push( this.search( client, 'cn=' + gr + ',' + groupsOu + ',' + dcString, groupMemberAttribute, userName, userAttribute ) );
                        } else {
                            const { cn, ou, groupMemberAttribute: grpMemberAttr, userAttribute: usrAttr } = gr;
                            if ( !cn || !ou ) return reject( new Error( "Invalid 'cn' or 'ou'" ) );
                            promises.push( this.search( client, 'cn=' + cn + ',' + ou + ',' + dcString, ( grpMemberAttr || groupMemberAttribute ), userName, ( usrAttr || userAttribute ) ) );
                        }
                    } );
                    Promise.all( promises )
                    .then( () => resolve() )
                    .catch( err => reject( err ) )
                    .finally( () => client.unbind() );
                } );
            } )
            .catch( reject );
        } );
    }
}