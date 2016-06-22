from ctrmisctk.utils import debyte, is_scalar, slacker_cacher_decorator
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
            if not self._value:
                self._value = ArithmeticList()
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


