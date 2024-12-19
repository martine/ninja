add_custom_command(OUTPUT
		"${CMAKE_CURRENT_BINARY_DIR}/manual.xml"
	COMMAND
		asciidoc --backend=docbook --doctype=book --out-file "${CMAKE_CURRENT_BINARY_DIR}/manual.xml" "${CMAKE_CURRENT_SOURCE_DIR}/manual.asciidoc"
)

add_custom_command(DEPENDS
		"${CMAKE_CURRENT_BINARY_DIR}/manual.xml"
	OUTPUT
		"${CMAKE_CURRENT_BINARY_DIR}/manual.html"
	COMMAND
		LibXslt::xsltproc --nonet "${CMAKE_CURRENT_SOURCE_DIR}/docbook.xsl" manual.xml > "${CMAKE_CURRENT_BINARY_DIR}/manual.html"
)

add_custom_target(doc ALL DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/manual.html")

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/manual.html" TYPE DOC)
