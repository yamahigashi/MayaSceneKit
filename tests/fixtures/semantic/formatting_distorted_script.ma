//Maya ASCII 2026 scene
requires maya "2026";
currentUnit -l centimeter -a degree -t film;

createNode     script     -n     "scrambledScript";
    setAttr ".stp" 0;
    setAttr ".st" 0;
    setAttr ".b"
        -type "string"
        "print(\"semantic fixture\")";

// End of formatting_distorted_script.ma
