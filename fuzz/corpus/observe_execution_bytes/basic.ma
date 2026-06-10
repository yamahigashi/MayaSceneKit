//Maya ASCII 2026 scene
requires maya "2026";
createNode SampleRenderOptions -n "SampleRenderOptionsNode";
    setAttr ".preRenderMel" -type "string" "print \"SampleCallback\";";
