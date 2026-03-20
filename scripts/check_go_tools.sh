#!/bin/bash
echo "PATH=$PATH"
echo ""
echo "Go bin contents:"
ls -la ~/go/bin/ 2>/dev/null
echo ""
echo "--- Checking Go tools ---"
for t in cariddi mantra dalfox katana gau gowitness; do
    f="$HOME/go/bin/$t"
    if [ -x "$f" ]; then
        echo "FOUND: $f"
    else
        echo "NOT in ~/go/bin: $t"
    fi
done
echo ""
echo "--- Checking /root/go/bin ---"
ls -la /root/go/bin/ 2>/dev/null || echo "/root/go/bin not accessible"
echo ""
echo "--- Which go ---"
which go 2>/dev/null && go env GOPATH 2>/dev/null
echo "GOPATH=$GOPATH"
echo "HOME=$HOME"
