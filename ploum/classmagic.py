"""Utilities that change class items"""


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

