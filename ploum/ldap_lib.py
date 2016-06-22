"""LDAP lib for introspection
←
Contains useful helpers"""
import logging
from .plumbing import LDAPAttribute

logger = logging.getLogger(__name__)


def build_properties(attr_dict):
    """Sort-of decorator to lately build properties on LDAP classes.

    Expects a PloumObj class"""
    def build_properties_real(cls):
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
                    if low not in self._attrs:
                        logger.error("Cannot find attribute %s", i)
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


