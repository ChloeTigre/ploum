# -*- encoding: utf-8
import logging
from ctrmisctk.utils import slacker_cacher_decorator
from .plumbing import AttributeFactory
import ldap
from ldap.ldapobject import LDAPObject, LDAPError

import ldap.schema

logger = logging.getLogger(__name__)
_ldap_conns = dict()


def get_ldap(identifier:str='DEFAULT', **kwargs) -> LDAPObject:
    """Get a LDAP connection.

    First time a connection is called and created successfully, the
    kwargs are used and passed to ldap.initialize.

    :param identifier: identifier of the connection
    """
    global _ldap_conns
    try:
        return _ldap_conns[identifier]
    except KeyError:
        logger.info('Creating new connection to LDAP: %s ', identifier)
    try:
        s = ldap.initialize(**kwargs)
        _ldap_conns[identifier] = s
        return s
    except (TypeError, LDAPError) as e:
        logger.error('Cannot get or initialize LDAP connection %s: %s', identifier, str(e))
        raise


def get_proper_type(result, all_types):
    return build_composedtype(result.get('objectClass', []), all_types)


@slacker_cacher_decorator
def build_composedtype(ocs, all_types):
    """Build a composed type from a list of object classes.

    all_types
    :param ocs: wanted object classes
    :param all_types: dict of all available types previously discovered"""
    typ = None
    met_types = []
    for i in ocs:
        if typ is None:
            typ = all_types[i]
        else:
            typ += all_types[i]
        for j in typ.sup_classes:
            if j not in met_types:
                typ += all_types[j]
                met_types.append(j)
        met_types.append(i)
    return typ


