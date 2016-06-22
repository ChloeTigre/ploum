# Ploum

A Python LDAP Object Mapper
           Unicorn ↗

## Concepts

LDAP works with objects aggregating several object classes. No override,
no conflict resolution, a LDAP object is a coherent entity honoring all
schemas its server has.

Python has a traditional object model, based on inheritance and overrides.

LDAP sorts (gives paths to) objects in a hierarchical namespace: objects are folded under
other special objects, namely organizational units.

Python does not care about this. Objects are first-class citizens and are
in the namespace you define.

LDAP provides a rich search syntax. Python does not.

## The idea

Ploum wants to make some LDAP objects easily manipulated by developers with
no clue of how LDAP works and who do not want to get past the steep learning curve.

Given a set of objectClass, Ploum builds Python objects with proper properties. It will
prepare pyldap calls to save items. It will also allow to search for items matching the
objectClasses and provided properties.

## Design principles

Ploum wants to work disconnected as much as possible. Hence the save, search and load
methods return callables that take a LDAP connection as parameter so they can be called
at another moment. 

Ploum wants to keep stuff simple. Hence only equality searches are implemented for the moment.
There is research work to build a simple and expressive syntax for other LDAP search modes;
namely, prefix searches and extensible match filters should in the end be supported.

## What Ploum does not perform

Ploum will not configure your LDAP server. Ploum will not establish and manage connections to
the LDAP server.
