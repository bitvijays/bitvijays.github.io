Learning from the CTF : Cryptography
====================================

This post (Work in Progress) lists the tips and tricks while doing Cryptography challenges during various CTF’s.

* Caesar cipher and substitution cipher can be solved by using Cryptool 1. Just check the Analysis option, there’s analysis for Symmetric Key,Asymmetric Key, Hash and others. Otherwise, a good website to solve substitution cipher is  `Quipqiup <http://quipqiup.com/>`_.

* If you get some text atleast few paragraphs and some random numbers as (1, 9, 4) (4, 2, 8) (4, 8, 3) (7, 1, 5) (8, 10, 1), it might mean (Paragraph, Line, Word). 

* If you get some ciphertext encrypted by XOR, `xortool <https://github.com/hellman/xortool>`_. It can help you to find the key length and the key.
 
