from ctrmisctk.utils import debyte, is_scalar, slacker_cacher_decorator
from .ploum import PloumObj
import ldap.schema
import logging

logger = logging.getLogger(__name__)


class AttributeFactory(object):
    """Factory class to build classes that describe attributes"""
    @staticmethod
    def build_attribute_class(atr, attrs_dict):
        typename = 'LDAPAttr_{}'.format(atr.names[0])
        attrtype = type(typename,
                        (LDAPAttribute,) + LDAPAttribute.__bases__,
                        dict(LDAPAttribute.__dict__))
        attrtype.properties = {
            'oid': atr.oid,
            'name': atr.names[0],
            'names': atr.names,
            'desc': atr.desc,
            'sup': atr.sup,
            'equality': atr.equality,
            'ordering': atr.ordering,
            'substring': atr.substr,
            'syntax': atr.syntax,
            'single_value': atr.single_value,
            'collective': atr.collective,
            'no_user_modification': atr.no_user_mod,
            'usage': atr.usage
        }
        return attrtype


class ComposableType(type):
    """A type that can be composed

    Used so we can compose objectClassen easily

    CT1 + CT2 = CT3 with composed entities'"""

    def __add__(self, other):
        newtype = type('clone_{}_{}'.format(self.__name__ , other.__name__),
                       self.__bases__, dict(self.__dict__))
        newtype.__doc__ = "Generated composition of {}, {}".format(
            self.__name__,
            other.__name__)
        for i in self.__dict__:
            if isinstance(self.__dict__[i], str):
                continue
            val = getattr(newtype, i, []) or []
            otherval = getattr(other, i, []) or []
            if (i in other.__dict__ and
                    isinstance(otherval, (type(None), list)) and
                    isinstance(val, (type(None), list))
                ):
                setattr(newtype, i, val + otherval)
        return newtype


class LDAPAttribute(object):
    """A class representing a LDAP attribute.

    Not meant to be instanciated directly. You are looking for
    `AttributeFactory`.`build_attribute_class`"""

    def __init__(self, value=None):
        self._dirty = False
        self._value = None
        self.set_value(value)
        self.properties = {}

    def get_base_state(self):
        """Return previous state of the item if any"""
        return getattr(self, '_base_state',
                       None if self.single_value else [])

    def set_clean(self):
        self._dirty = False

    def set_value(self, value):
        """Set value of this LDAPAttribute"""
        self._dirty = True
        self._base_state = self._value
        if self.single_value:
            if is_scalar(value):
                self._value = value
            else:
                logger.warning("Wrong initial value for scalar type %s: %s",
                               type(self), value)
        else:
            self._value = ArithmeticList()
            if value:
                self._value += value
            logger.info("Set value of %s to %s", self, self._value)

    def __add__(self, other):
        """Update value of this LDAP Attribute.

        For single value, replace _value by other
        Else append new value to _value"""
        self._dirty = True
        self._base_state = self._value
        if self.single_value:
            if not is_scalar(other):
                self._value = debyte(other[0])
            else:
                self._value = debyte(other)
        else:
            if other:
                self._value += debyte(other)
        return self

    @property
    def dirty(self):
        return self._dirty

    @property
    def oid(self):
        return self.properties.get('oid')

    @property
    def name(self):
        return self.properties.get('name')

    @property
    def names(self):
        return self.properties.get('names')

    @property
    def desc(self):
        return self.properties.get('desc')

    @property
    def obsolete(self):
        return self.properties.get('obsolete', False)

    @property
    def sup(self):
        return self.properties.get('sup')

    @property
    def equality(self):
        return self.properties.get('equality')

    @property
    def ordering(self):
        return self.properties.get('ordering')

    @property
    def substring(self):
        return self.properties.get('substring')
    pass

    @property
    def syntax(self):
        return self.properties.get('syntax')

    @property
    def single_value(self):
        return self.properties.get('single_value', False)

    @property
    def collective(self):
        return self.properties.get('collective')

    @property
    def no_user_modification(self):
        return self.properties.get('no_user_modification')

    @property
    def usage(self):
        return self.properties.get('usage')

    @property
    def value(self):
        return self._value

    def __str__(self):
        return '{}({})'.format(self.__class__.__name__,
                               repr(self._value))

    def portable_value(self):
        if self.single_value:
            if isinstance(self._value, bytes):
                s = self._value.decode('utf-8')
            else:
                s = str(self._value)
            return s
        else:
            return list(self._value)

    json_helper = portable_value


class ArithmeticList(list):
    """A list on which you can + and - items"""

    def __add__(self, other):
        res = ArithmeticList(self)
        if not is_scalar(other):
            for i in other:
                if debyte(i) not in self:
                    res.append(debyte(i))
            res._clean = False
        elif debyte(other) not in self:
            res._clean = False
            res.append(debyte(other))
        return res

    def __sub__(self, other):
        if other in self:
            self.remove(debyte(other))
            self._clean = False
        else:
            raise ValueError('Cannot remove item from list not having it')

    def __init__(self, iterable=None):
        if is_scalar(iterable) and iterable:
            iterable = [debyte(iterable)]
        if iterable:
            for i in set(iterable):
                j = debyte(i)
                if j not in self:
                    self += j
        super().__init__(set(iterable or []))

    def set_clean(self):
        """Mark this list clean and save its base state"""
        self._clean = True
        self._base_state = list(self)

    def get_base_state(self):
        return getattr(self, '_base_state', [])

    def is_clean(self):
        return hasattr(self, '_clean', False)


def build_ldapclass(object_class, attrdefs, all_types):
    """Build a Python class for a LDAP objectClass

    :param object_class: objectClass for which we want a python class
    :param attrdefs: dict of possible attributes introspecet
    :param all_types: dict referencing all introspected types
    :return: python class"""
    if object_class:
        c = type('LDAPEntity_{}'.format(object_class.names[0]),
                 (PloumObj,),
                 {
                     'names': ArithmeticList(object_class.names or []),
                     'must_fields': ArithmeticList(object_class.must or []),
                     'may_fields': ArithmeticList(object_class.may or []),
                     'sup_classes': ArithmeticList(object_class.sup or []),
                     'obsolete': object_class.obsolete,
                     'oid': object_class.oid,
                     'attr_types': attrdefs,
                     'datadict': all_types
                 }
                 )
        return c


@slacker_cacher_decorator
def load_schemas(ldap_conn) -> dict:
    """Load schemas from a LDAP connection and return them

    :param ldap_conn: a LDAP connection"""
    subschema_res = ldap_conn.search_s(
        base='', scope=ldap.SCOPE_BASE,
        filterstr='(objectClass=*)', attrlist=['subschemaSubEntry'])
    try:
        subschemacn = subschema_res[0][1]['subschemaSubentry'][0].decode('utf-8')
    except (IndexError, KeyError) as e:
        logger.fatal(
            'Cannot load subschema. Check if available and grant access to it.\n'
            'Not proceeding further because LDAP access is broken:\n%s', e)
        raise
    logger.debug('Subschema: %s', subschemacn)
    logger.debug('Loading LDAP schema')
    schemata_r = ldap_conn.search_s(
        base=subschemacn, scope=ldap.SCOPE_BASE, attrlist=['*', '+'])
    schemata = ldap.schema.SubSchema(schemata_r[0][1])
    object_classes = schemata.tree(ldap.schema.ObjectClass)
    attrs_types = schemata.tree(ldap.schema.AttributeType)
    datadict = {}
    typedict = {}
    for t in attrs_types:
        typ = schemata.get_obj(ldap.schema.AttributeType, t)
        if not typ:
            logger.error("Cannot find type for %s", t)
            continue
        for n in typ.names:
            typedict[n] = AttributeFactory.build_attribute_class(typ, attrs_types)
    for o in object_classes:
        obj = schemata.get_obj(ldap.schema.ObjectClass, o)
        if obj:
            c = build_ldapclass(obj, typedict, datadict)
            for i in obj.names:
                datadict[i] = c
                datadict[i.encode('utf-8')] = c
    return datadict, typedict


