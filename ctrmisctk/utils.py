"""Misc Python utilities"""
import sortedcontainers
import functools


def make_a_list(iterable):
    """Make a list from dict, set, tuple, list

    :param iterable: wanted iterable
    :return: list"""
    if isinstance(iterable, dict):
        return [a for a in iterable.values()]
    elif isinstance(iterable, (list, set, tuple)):
        return [a for a in iterable]


def dict_deep_update(d1, *args):
    """Update d1 with other maps passed as args
    :param d1: dictionary to update
    :param ...: maps to take the updates from, treated in order"""
    for d2 in args:
        for k, v in d2.items():
            if k not in d1:
                d1[k] = v
            elif isinstance(d1[k], dict):
                dict_deep_update(d1[k], v)
            elif isinstance(d1[k], list) and isinstance(d2[k], list):
                for i in d2[k]:
                    if i not in d1[k]:
                        d1[k].append(i)
            elif d1[k] != v:
                d1[k] = v


def recursive_sort(l):
    """sort a list recursively
    :param l: the list to sort

    Has bad hack to ensure we do not sort de/serialized IP tuples.
    To be phased out someday."""
    # specific attrs shitty hack - avoid to sort IP tuple
    if (isinstance(l, list) and len(l) == 3 and str(l[1]).isnumeric()
       and not str(l[0]).isnumeric()):
        return
    try:
        l.sort()
    except:
        pass
    try:
        items = l.values()
    except:
        items = l
    if items is None: return
    try:
        for i in items:
            if isinstance(i, list):
                recursive_sort(i)
    except:
        return
    """Get the real function maybe with docstring

    :return: callable"""
    try:
        return getattr(o, '__func__', o)
    except:
        if hasattr(o, 'im_func'):
            return o.im_func
        return o


def inherit_docs(cls):
    for name, func in vars(cls).items():
        realfunc = _get_real_function(func)
        if realfunc and not _interesting_docstring(realfunc.__doc__):
            for parent in cls.__bases__:
                parfunc = _get_real_function(getattr(parent, name, None))
                if parfunc and _interesting_docstring(parfunc.__doc__):
                    if realfunc.__doc__ and ':parentdoc:' in realfunc.__doc__:
                        realfunc.__doc__ = realfunc.__doc__.replace(
                                ':parentdoc:',
                                parfunc.__doc__
                                )
                    else:
                        realfunc.__doc__ = parfunc.__doc__
                    func.__doc__ = realfunc.__doc__
                    break
    return cls


def test_inherit_docs():
    class A(object):
        @classmethod
        def bla(cls):
            "bla: A classmethod"

        @staticmethod
        def bli():
            """bli: A staticmethod"""

        def blo(self):
            """blo: A method"""

    @inherit_docs
    class B(A):
        @classmethod
        def bla(cls):
            super().bla()

        @staticmethod
        def bli():
            super().bli()

        def blo(self):
            super.blo()

    a = A()
    b = B()
    assert A.bla.__doc__ == B.bla.__doc__
    assert B.bli.__doc__ == B.bli.__doc__
    assert a.blo.__doc__ == b.blo.__doc__


_cache_answers = {}


def slacker_cacher_decorator(f):
    """A caching decorator for short-term invariant results.

    When applied to a function then this function will be called only once with a
    given argument set. The cache is done using a str() serialization of a tuple
    containing the function and its parameters.

    If you want to bypass cache, add a uncache=True parameter to the function
    arguments.

    :param f: function to decorate

    :return: decorated function
    """
    global _cache_answers
    @functools.wraps(f)
    def _(*a, **k):
        if k.pop('uncache', None) is not None or repr([f, a, k]) not in _cache_answers:
            _cache_answers[repr([f, a, k])] = f(*a, **k)
        return _cache_answers[repr([f, a, k])]
    return _


def is_scalar(thing):
    return isinstance(thing, (type(None), bytes, str)) or not hasattr(thing, '__iter__')


def debyte(item):
    if isinstance(item, bytes):
        return item.decode('utf-8')
    return item


def bytify(item):
    if isinstance(item, str):
        return item.encode('utf-8')
    return item
