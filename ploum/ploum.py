"""Ploum"""

import logging
from . import plumbing
from .ldap_utils import get_proper_type
from .ldap_lib import build_properties
from copy import deepcopy
from ctrmisctk.utils import is_scalar, bytify
import ldap.modlist

logger = logging.getLogger(__name__)


class PloumObj(object, metaclass=plumbing.ComposableType):
    """A base class for PloumObj.

    Works without the need to be connected.

    Extended by actual LDAP entities to have functionalities.
    :param dn: optional dn for this LDAP entity
    :param initial_attrs: optional initial attributes of this LDAP entity

    initial_attrs must implement a mapping interface (multidict) and be
    iterable over items(), values() and keys()."""
    virtual_fields = (
        'entryDN', 'subschemaSubentry', 'modifyTimestamp', 'modifiersName',
        'creatorsName', 'creatorsTimestamp', 'hasSubordinates', 'entryCSN',
        'createTimestamp', 'structuralObjectClass', 'entryUUID',
        'contextCSN',
    )

    def __new__(cls, *args, **kwargs):
        obj = super().__new__(cls)
        if hasattr(obj, 'attr_types'):
            pass
        return obj

    def __init__(self, dn=None, initial_attrs=None):
        self._already_exists = False
        self._dn = None
        self._attrs = {}
        self._deleted = False
        self._base_state = None
        if dn and initial_attrs:
            self.populate(dn, initial_attrs)

    def populate(self, dn, attrs):
        self.dn = dn
        self._already_exists = True
        for (i, j) in attrs.items():
            low = i.lower()
            if low in list(a.lower() for a in self.virtual_fields):
                continue
            if low not in ('objectclass',) + tuple(
                    a.lower() for a in self.may_fields + self.must_fields):
                logger.error('%s: cannot assign unknown attribute %s', type(self), i)
                raise KeyError('Cannot assign unknown attribute !')
            if low not in self._attrs:
                self._attrs[low] = self.attr_types[i]()
            self._attrs[low] += j
            self._attrs[low].set_clean()
        self._base_state = deepcopy(self._attrs)

    def __repr__(self):
        return '{}({}, {})'.format(self.__class__.__name__, repr(self.dn), repr(self._attrs))

    @classmethod
    def get_minimal_filter(cls):
        """Return the minimal filter conditionswanted for this LDAP entity.
        It will be &ed to any provided filter"""
        return '(objectClass=*)'

    def get_old_and_current_state(self) -> list:
        """Generate a modification list for this PloumObj"""
        old = {}
        new = {}
        old_item = self._base_state
        for (k, v) in self._attrs.items():
            if old_item:
                old[k] = old_item[k]._value
            else:
                old[k] = v.get_base_state()
            if is_scalar(old[k]):
                logger.debug("Wrapping in array: %s", old[k])
                old[k] = [bytify(old[k])]
            if is_scalar(v.value):
                new[k] = [bytify(v.value)]
            else:
                new[k] = list(bytify(a) for a in v.value or [])
            logger.info("New: %s → %s", k, new[k])
        return old, new

    def mark_clean(self):
        """Mark all attributes as clean"""
        for i in self._attrs.values():
            i.set_clean()
        return True

    def mark_deleted(self):
        self._deleted = True
        return True

    @classmethod
    def search_all_ldap(cls, base_dn=None,
                        scope=ldap.SCOPE_SUBTREE, filterstr=None,
                        force_full_dn=False,
                        **kwargs):
        """Search all items that match the provided '=' criteria

        :param base_dn: where we will search
        :param scope: scope of the search
        :param filterstr: optional filter
        :param force_full_dn: if True, take provided filterstr literally
        :return: callable(ldapconn) that will make a list of matches"""
        if not base_dn:
            raise ValueError('No base_dn provided. Cannot search.')
        if not force_full_dn:
            filterstr = filterstr or '(&{})'.format(
                ''.join(list(
                    '({}={})'.format(k, v) for (k, v) in kwargs.items())
                )
            )
            if filterstr == '(&)':
                filterstr = '(objectClass=*)'
            filterstr = "(&{}{})".format(filterstr, cls.get_minimal_filter())
            return lambda ldapconn: [
                get_proper_type(attr, cls.datadict)(dn, attr)
                for (dn, attr) in ldapconn.search_ext_s(
                    cls.local_dn() + base_dn, scope, filterstr=filterstr, attrlist=['*', '+'])]
        else:
            return lambda ldapconn: [
                get_proper_type(attr, cls.datadict)(dn, attr)
                for (dn, attr) in ldapconn.search_ext_s(
                    base_dn, ldap.SCOPE_BASE, filterstr='(objectClass=*)',
                    attrlist=['*', '+']
                )
                ]

    @classmethod
    def local_dn(cls):
        """Return local_dn, where one should search entities more precisely.

        Not 100% useful in small trees, but allows to restrict search to a given tree
        """
        return ""

    @property
    def dn(self):
        """The DN of a LDAP entity
        --
        str"""
        return self._dn

    @dn.setter
    def dn(self, value):
        self._dn = value

    def save_ldap(self) -> 'callable(ldapconn)':
        """Prepare save of an item. Return a callable that eats the connection.

        :return: lambda(SimpleLDAPObject) which, when called, will persist the item
            and mark it clean"""
        to_create = True
        logger.info("saving entity %s: %s", self.names, self.dn)
        (initial_state, new_state) = self.get_old_and_current_state()
        if self._already_exists:
            to_create = False
            ldif = ldap.modlist.modifyModlist(initial_state, new_state, ignore_oldexistent=1)
        else:
            ldif = ldap.modlist.addModlist(new_state)
        logger.info("to-create: %s - Will save %s from\n[\n%s,\n%s]", to_create, ldif, initial_state, new_state)
        if to_create:
            return lambda ldapconn: ldapconn.add_s(self.dn, ldif) and self.mark_clean()
        return lambda ldapconn: ldapconn.modify_s(self.dn, ldif) and self.mark_clean()

    def delete_ldap(self) -> 'callable(ldapconn)':
        """Prepare delete of an item. Return a callable that eats the connection.

        :return: lambda(SimpleLDAPObject) which when called will delete the entry
        and mark it deleted"""
        return lambda ldapconn: ldapconn.delete_s(self.dn) and self.mark_deleted()


class LDAPFactory(object):
    """Factory class to build LDAP classes

    Optionally one may establish_connection before doing the get_class calls.
    This makes passing the conn parameter optional.
    """
    __module__ = __name__
    objclasses = None
    conn = None
    base_dn = None

    @classmethod
    def establish_connection(cls, ldap_url, credentials, base_dn):
        """Establish a connection to a LDAP

        :param ldap_url: URL of LDAP to connect to
        :param credentials: tuple (login, password) of credentials passed to bind
        :return: None
        """
        cls.conn = get_ldap('LDAPFactory', uri=ldap_url)
        cls.conn.bind(*credentials)
        cls.base_dn = base_dn
        cls.objclasses = None

    @classmethod
    def get_class(cls, objectclasses: (str,), conn: "ldap connection"=None) -> PloumObj:
        """Get a Python class from one or more objectclasses

        :param objectclasses: string objectClass or tuple of strings objectClasses
        :return: python class"""
        if not conn and not cls.conn:
            raise RuntimeError('Cannot get_class without establish_connection before')
        elif not conn and cls.conn:
            conn = cls.conn
        cls.objclasses, typedict = plumbing.load_schemas(conn)
        if isinstance(objectclasses, str):
            objectclasses = (objectclasses,)
        typ = get_proper_type(dict(objectClass=objectclasses), cls.objclasses)
        typ.__name__ = 'LDAP_{}'.format('_'.join(objectclasses))
        return build_properties(typedict)(typ)


__all__ = ["PloumObj", "LDAPFactory", ]