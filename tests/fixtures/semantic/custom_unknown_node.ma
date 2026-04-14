//Maya ASCII 2026 scene
requires maya "2026";
requires "myCustomPlugin" "1.0";
currentUnit -l centimeter -a degree -t film;
createNode myCustomNode -n "customNode1";
    setAttr ".flag" 1;

// End of custom_unknown_node.ma
