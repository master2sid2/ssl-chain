# Demo recording for the README. Regenerate with "make demo" (needs Docker).
# The certificates are made up on the fly by make-certs.sh for example.com.

Output docs/demo/ssl-chain.gif

Set Shell "bash"
Set FontSize 14
Set Width 900
Set Height 820
Set Padding 18
Set Theme "Dracula"
Set TypingSpeed 35ms
Set Framerate 24

Hide
Type "export PATH=$PWD/bin:$PATH HOME=$(mktemp -d) PS1='$ ' D=$PWD; cd $(mktemp -d) && sh $D/docs/demo/make-certs.sh && clear" Enter
Sleep 4s
Show

Type "ssl-chain fullchain.pem" Sleep 400ms Enter
Sleep 5s

Type "clear; ssl-chain shop.crt root.crt" Sleep 400ms Enter
Sleep 5s

Type "clear; ssl-chain shop.crt shop.csr shop.key" Sleep 400ms Enter
Sleep 5s
