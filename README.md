# idemixjs

*`transform`*

Outil à utiliser pour transformer les fichier de la lib Apache Milagro en module.
Importer la lib auparavant

Dans js/ctx.js ajoute la ligne console.log(moduleName)

  prepareModule = function (moduleName, fileName, propertyName) {
=>        console.log(moduleName);
        if (!propertyName) {
            propertyName = moduleName;
        }

Lance le programme et regarde le lequel sur lequel il bloque.
ensuite ./transform <nom du module en minuscule>

et tu continues jusqu à plus d erreurs



* Problem FP avec le BIG non reconnu

Modifie ton fichier js/fp.go de cette manière
45c45
<             if (x instanceof BIG) {
---
>             if (x instanceof ctx.BIG) {

