"""LDAP lib for introspection

Contains useful helpers"""
import logging
import ldap
import ldap.schema
import ldap.modlist
from ldap.ldapobject import LDAPObject, LDAPError
from copy import deepcopy
from ctrmisctk.utils import slacker_cacher_decorator, is_scalar, debyte, bytify


_ldap_conns = dict()
logger = logging.getLogger(__name__)


def build_properties(attr_dict):
    def build_properties_real(cls):
        """Sort-of decorator to lately build properties on LDAP classes.

        Expects a LDAPObj class"""
        for i in cls.may_fields + cls.must_fields:
            def _get(self, low=i.lower()):
                return self._attrs.get(low)

            def _set(self, value, low=i.lower()):
                if self._mode == 'self_update':
                    self._attrs[low].set_value(value)
                    return
                logger.info("Setting value to %s", value)
                if isinstance(value, LDAPAttribute):
                    self._attrs[low] = value
                else:
                    self._attrs[low] += value
                logger.info("Value is now %s", self._attrs[low]._value)
                logger.debug("Attr type: %s → %s", type(self._attrs[low]), self._attrs[low])
                assert isinstance(self._attrs[low], LDAPAttribute)
            setattr(cls, i,
                    property(
                        fget=_get, fset=_set,
                        doc="""
            {0} property (automatically added by ldap_lib.py)

            Description: {1.properties[desc]}
            Single value? {1.properties[single_value]}
            Usage: {1.usage}
            --
            {2}""".format(
                            i,
                            attr_dict[i],
                            'str' if cls.attr_types[i].properties['single_value']
                            else 'list(str)'
                        )))
        return cls
    return build_properties_real


class AttributeFactory(object):
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


class LDAPObj(object, metaclass=ComposableType):
    """A base class for LDAPObj.

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
        """Generate a modification list for this LDAPObj"""
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
    __module__ = __name__
    __qualname__ = 'LDAPFactory'
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
    def get_class(cls, objectclasses: (str,)) -> LDAPObj:
        """Get a Python class from one or more objectclasses

        :param objectclasses: string objectClass or tuple of strings objectClasses
        :return: python class"""
        if not cls.conn:
            raise RuntimeError('Cannot get_class without establish_connection before')
        cls.objclasses, typedict = load_schemas(cls.conn)
        if isinstance(objectclasses, str):
            objectclasses = (objectclasses,)
        typ = get_proper_type(dict(objectClass=objectclasses), cls.objclasses)
        typ.__name__ = 'LDAP_{}'.format('_'.join(objectclasses))
        return build_properties(typedict)(typ)


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


def get_proper_type(result, all_types):
    return build_composedtype(result.get('objectClass', []), all_types)


@slacker_cacher_decorator
def build_composedtype(ocs, all_types):
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
            'Cannot load subschema. Check if available and grant ACL to it.\n'
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


def build_ldapclass(object_class, attrdefs, all_types):
    """Build a Python class for a LDAP objectClass

    :param object_class: objectClass for which we want a python class
    :param attrdefs: dict of possible attributes introspecet
    :param all_types: dict referencing all introspected types
    :return: python class"""
    if object_class:
        c = type('LDAPEntity_{}'.format(object_class.names[0]),
                 (LDAPObj,),
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


def get_ldap(identifier:str='DEFAULT', **kwargs) -> LDAPObject:
    """Get a LDAP connection.

    First time a connection is called and created successfully, the
    kwargs are used and passed to ldap.initialize.

    :param identifier: identifier of the connection
    """
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
