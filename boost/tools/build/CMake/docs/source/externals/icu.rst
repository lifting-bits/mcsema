.. index:: ICU, external dependency
.. _icu:


ICU (International Components for Unicode)
==========================================

If ``WITH_ICU`` is ``ON``, ICU is detected via the standard cmake
``find_package(ICU)``.  The following variables are set:

+-----------------------+----------------------------------------+
|``ICU_FOUND``          |ON if icu was found                     |
+-----------------------+----------------------------------------+
|``ICU_I18N_FOUND``     |ON if the i18n part (whatever that is)  |
|                       |of ICU was found.                       |
+-----------------------+----------------------------------------+
|``ICU_INCLUDE_DIRS``   |path to ICU headers                     |
+-----------------------+----------------------------------------+
|``ICU_LIBRARIES``      |full paths to ICU libraries             |
+-----------------------+----------------------------------------+
|``ICU_I18N_LIBRARIES`` |full paths to the i18n libraries        |
+-----------------------+----------------------------------------+
