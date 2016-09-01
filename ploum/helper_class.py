# -*- encoding: utf-8
"""Ploum

LDAP Helper class.

This class may be extended by child classes to ease development
of Ploum classes.

The following code shows how to create a Ploum class for emailDomain
.. code:: python

    _baseMaildomain = ploum.LDAPFactory.get_class('mailDomain')

    class EmailDomain(LDAPHelper, _baseMaildomain):
        EXT_DN = "ou=mailDomains,dc=mail,"
        OBJECT_CLASSES = ('mailDomain',)
"""

import logging
from . import plumbing
from . import ploum
logger = logging.getLogger(__name__)


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

    @classmethod
    def search_all(cls, **kwargs):
        d = cls()
        def search(conn):
            return [cls(a) for a in d.search_all_ldap(**kwargs)(conn)]
        return search

    def __init__(self, obj=None):
        super(LDAPHelper, self).__init__()
        if isinstance(obj, ploum.PloumObj):
            # eat the attributes of this PloumObj.
            self.__dict__.update(obj.__dict__)
        self._pk = dict(dn=self.dn)
        self._mode = 'normal'


__all__ = ['LDAPHelper', ]
