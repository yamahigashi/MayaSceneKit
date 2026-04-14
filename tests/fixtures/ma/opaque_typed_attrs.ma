//Maya ASCII 2026 scene
requires maya "2026";
createNode mesh -n "meshShape1";
    setAttr ".fc[0]" -type "polyFaces" f 4 0 1 2 3 mu 0 4 0 1 2 3;
    setAttr ".cd" -type "dataPolyComponent" Index_Data Edge 2 0 1;
createNode nurbsCurve -n "curveShape1";
    setAttr ".cc" -type "nurbsCurve" 3 1 0 no 3 6 0 0 0 1 1 1 0 0 0 1 1 0 2 0 0 3 1 0;
createNode script -n "scriptNode1";
    setAttr ".b" -type "string" "print \"opaque ok\";";
createNode file -n "file1";
    setAttr ".ftn" -type "string" "textures/albedo.png";
