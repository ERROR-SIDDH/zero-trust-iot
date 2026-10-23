set(zt_examples
    context-drift-test
    micro-segmentation-test
    trust-scorer-test
    mitm/mitm-attack
    mitm/mitm-mitigation
    spoofing/spoofing-attack
    spoofing/spoofing-mitigation
    unauthorized-access/unauthorized-access-attack
    unauthorized-access/unauthorized-access-mitigation
)

foreach(example ${zt_examples})
  get_filename_component(name ${example} NAME)
  build_lib_example(
    NAME ${name}
    SOURCE_FILES ${example}.cc
    LIBRARIES_TO_LINK
      ${libzero-trust-iot}
      ${libpoint-to-point}
      ${libapplications}
  )
endforeach()
