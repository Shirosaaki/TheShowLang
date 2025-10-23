# TheShowLang

## S-Expression

Deschodt [function](params) -> [return_type] => create the function [function_name] with [params] and return [return_type]
Deschodt Eric() -> int => create the main function Eric with no parameters and return int

eric [var_name] -> [type] => create the variable [var_name] with type [type]
eric [var_name] = [value] => create the variable [var_name] and assign it the value [value]

erif [condition]:
    [code_block]
deschelse:
    [code_block]
=> if-else statement

aer [loop_variable] in [range]:
    [code_block]
=> for loop

darius [condition]:
    [code_block]
=> while loop

peric("message") => print the message to the console
peric("hello, {var_name}!") => print the message with variable interpolation

deschodt [value] => return the value from a function
deschodt => return from a function without a value

destruct [structure_name]:
    [type] [field_name]
    [type] [field_name]
=> destructure the structure [structure_name] into its fields

darius (true):
    erif (x > 10):
        deschreak  # break
    erif (x == 5):
        deschontinue  # continue

desenum Couleur:
    ROUGE
    VERT
    BLEU
=> define an enumeration Couleur with values ROUGE, VERT, and BLEU

desnote ceci est un commentaire => create a comment

ertry:
    [code]
ercatch:
    [code si erreur]
=> try-catch block