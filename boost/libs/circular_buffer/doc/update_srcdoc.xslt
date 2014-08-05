<?xml version='1.0' encoding='iso-8859-1'?>
<!--
Helper XSL transformation updating source code documentation sections
in the specified HTML file.

Copyright (c) 2003-2008 Jan Gaspar

Use, modification, and distribution is subject to the Boost Software
License, Version 1.0. (See accompanying file LICENSE_1_0.txt or copy at
http://www.boost.org/LICENSE_1_0.txt)
-->

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

  <xsl:import href="copy.xslt"/>

  <xsl:output method="html" version="1.0" encoding="iso-8859-1" indent="yes" omit-xml-declaration="yes" media-type="text/html"/>

  <xsl:param name="srcdoc"/>

  <xsl:template match="div[contains(@id, 'srcdoc')]">
    <xsl:copy-of select="document($srcdoc)//body/div[@id=current()/@id]"/>
  </xsl:template>

</xsl:stylesheet>
