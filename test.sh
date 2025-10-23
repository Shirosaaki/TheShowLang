#!/bin/bash

# Vide le fichier de log
> test.log

# Compte le nombre de fichiers correspondant au pattern
count=$(ls examples/example*.tslang 2>/dev/null | wc -l)

# Boucle sur chaque fichier
for ((i=1; i<=count; i++)); do
    echo "===== Running example$i.tslang =====" | tee -a test.log
    ./bin/tsc "examples/example$i.tslang" a.out >> test.log 2>&1
    ./a.out >> test.log 2>&1
    echo "exit$?" | tee -a test.log
    echo "" >> test.log
done
