//Maya ASCII 2026 scene
requires maya "2026";
createNode script -n "ExampleScript";
    setAttr ".b" -type "string" "print \"Sample\";";
