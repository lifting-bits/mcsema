boost_add_library(math_tr1

	assoc_laguerre.cpp assoc_legendre.cpp beta.cpp
	comp_ellint_1.cpp comp_ellint_2.cpp comp_ellint_3.cpp
	cyl_bessel_i.cpp cyl_bessel_j.cpp cyl_bessel_k.cpp
	cyl_neumann.cpp ellint_1.cpp ellint_2.cpp ellint_3.cpp
	expint.cpp hermite.cpp laguerre.cpp legendre.cpp
	riemann_zeta.cpp sph_bessel.cpp sph_legendre.cpp
	sph_neumann.cpp

	SHARED_COMPILE_FLAGS "-DBOOST_MATH_TR1_DYN_LINK=1"
	COMPILE_FLAGS "-I${CMAKE_CURRENT_SOURCE_DIR}"
)

boost_add_library(math_tr1f

	assoc_laguerref.cpp assoc_legendref.cpp betaf.cpp
	comp_ellint_1f.cpp comp_ellint_2f.cpp comp_ellint_3f.cpp
	cyl_bessel_if.cpp cyl_bessel_jf.cpp cyl_bessel_kf.cpp
	cyl_neumannf.cpp ellint_1f.cpp ellint_2f.cpp ellint_3f.cpp
	expintf.cpp hermitef.cpp laguerref.cpp legendref.cpp
	riemann_zetaf.cpp sph_besself.cpp sph_legendref.cpp
	sph_neumannf.cpp

	SHARED_COMPILE_FLAGS "-DBOOST_MATH_TR1_DYN_LINK=1"
	COMPILE_FLAGS "-I${CMAKE_CURRENT_SOURCE_DIR}"
)

boost_add_library(math_c99

	acosh.cpp asinh.cpp atanh.cpp cbrt.cpp copysign.cpp erfc.cpp
	erf.cpp expm1.cpp fmax.cpp fmin.cpp fpclassify.cpp hypot.cpp
	lgamma.cpp llround.cpp log1p.cpp lround.cpp nextafter.cpp
	nexttoward.cpp round.cpp tgamma.cpp trunc.cpp

	SHARED_COMPILE_FLAGS "-DBOOST_MATH_TR1_DYN_LINK=1"
	COMPILE_FLAGS "-I${CMAKE_CURRENT_SOURCE_DIR}"
)

boost_add_library(math_c99f

	acoshf.cpp asinhf.cpp atanhf.cpp cbrtf.cpp copysignf.cpp
	erfcf.cpp erff.cpp expm1f.cpp fmaxf.cpp fminf.cpp
	fpclassifyf.cpp hypotf.cpp lgammaf.cpp llroundf.cpp log1pf.cpp
	lroundf.cpp nextafterf.cpp nexttowardf.cpp roundf.cpp
	tgammaf.cpp truncf.cpp

	SHARED_COMPILE_FLAGS "-DBOOST_MATH_TR1_DYN_LINK=1"
	COMPILE_FLAGS "-I${CMAKE_CURRENT_SOURCE_DIR}"
)

try_compile(HAS_LONG_DOUBLE_SUPPORT
	${CMAKE_CURRENT_SOURCE_DIR}/../../config/
	${CMAKE_CURRENT_SOURCE_DIR}/../../config/
	has_long_double_support)

IF (HAS_LONG_DOUBLE_SUPPORT)
	boost_add_library(math_tr1l

		assoc_laguerrel.cpp assoc_legendrel.cpp betal.cpp
		comp_ellint_1l.cpp comp_ellint_2l.cpp comp_ellint_3l.cpp
		cyl_bessel_il.cpp cyl_bessel_jl.cpp cyl_bessel_kl.cpp
		cyl_neumannl.cpp ellint_1l.cpp ellint_2l.cpp ellint_3l.cpp
		expintl.cpp hermitel.cpp laguerrel.cpp legendrel.cpp
		riemann_zetal.cpp sph_bessell.cpp sph_legendrel.cpp
		sph_neumannl.cpp

		SHARED_COMPILE_FLAGS "-DBOOST_MATH_TR1_DYN_LINK=1"
		COMPILE_FLAGS "-I${CMAKE_CURRENT_SOURCE_DIR}"
	)

	boost_add_library(math_c99l

		acoshl.cpp asinhl.cpp atanhl.cpp cbrtl.cpp copysignl.cpp
		erfcl.cpp erfl.cpp expm1l.cpp fmaxl.cpp fminl.cpp
		fpclassifyl.cpp hypotl.cpp lgammal.cpp llroundl.cpp log1pl.cpp
		lroundl.cpp nextafterl.cpp nexttowardl.cpp roundl.cpp
		tgammal.cpp truncl.cpp

		SHARED_COMPILE_FLAGS "-DBOOST_MATH_TR1_DYN_LINK=1"
		COMPILE_FLAGS "-I${CMAKE_CURRENT_SOURCE_DIR}"
	)
ELSE ()
	colormsg(RED "+-- long double not supported, skipping math_*l libraries.")
ENDIF ()
