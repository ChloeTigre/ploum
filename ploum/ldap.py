"""Bundle for Flatrack LDAP entities.

Here as an example"""
import logging

from . import ldap_lib
logger = logging.getLogger(__name__)
TYPE_MAPPING = dict()


class LDAPHelper(object):
    EXT_DN = ""
    OBJECT_CLASSES = tuple()

    @classmethod
    def get_minimal_filter(cls):
        return '(&{})'.format(''.join(list(
            '(objectClass={})'.format(a) for a in cls.OBJECT_CLASSES)))

    @classmethod
    def local_dn(cls):
        return cls.EXT_DN

    def self_update(self, updict):
        self._mode = 'self_update'
        for k, v in updict.items():
            try:
                setattr(self, k, v)
                logger.info("updating %s to %s → %s", k, v, getattr(self, k))
            except AttributeError:
                pass
        self._mode = 'normal'
        return True

    @property
    def dn(self):
        """Distinguished name of LDAP entity
        --
        str"""
        return self._dn

    def __init__(self, obj):
        super(LDAPHelper, self).__init__()
        if isinstance(obj, ldap_lib.LDAPObj):
            # eat the attributes of this LDAPObj.
            self.__dict__.update(obj.__dict__)
        self._pk = dict(dn=self.dn)
        self._mode = 'normal'

_baseMaildomain = ldap_lib.LDAPFactory.get_class('mailDomain')

# Example LDAP entity.


class EmailDomain(LDAPHelper,
                  _baseMaildomain
                  ):
    """EmailDomain represents LDAP objects with objectClass=mailDomain
    """
    EXT_DN = "ou=mailDomains,dc=mail,"
    OBJECT_CLASSES = ('mailDomain',)

