#!/usr/bin/env python2

import angr

#TODO: will need to be moved/modified to fit into class structure

def get_bindiff(filename1, filename2):

  project_one = angr.Project(filename1, load_options={'auto_load_libs':False})
  project_two = angr.Project(filename2, load_options={'auto_load_libs':False})
  
  bindiff = project_one.analyses.BinDiff(project_two)
  
  return bindiff


def compare_bindiff(bindiff):

  assert bindiff, "BinDiff not initialized"
  
  identical_funcs = bindiff.identical_functions
  differing_funcs = bindiff.differing_functions
  unmatched_funcs = bindiff.unmatched_functions
  differing_const = bindiff.blocks_with_differing_constants
  
  block_matches = []
  
  for dif_a, dif_b in differing_funcs:
    assert dif_a and dif_b
    func_diff = bindiff.get_function_diff(dif_a, dif_b)
    block_matches += {(x.addr, y.addr) for x, y in func_diff.block_matches}
    
  return {'identical_funcs': identical_funcs,
          'differing_funcs': differing_funcs,
          'unmatched_funcs': unmatched_funcs,
          'differing_const': differing_const,
          'block_matches': block_matches
         }

# test compare
# dif = get_bindiff('fauxware', 'ais3_crackme')
# comp = compare_bindiff(dif)
# print comp
# dif = get_bindiff('CADET_00001', 'CADET_00001')
# comp = compare_bindiff(dif)
# assert not comp['differing_funcs']
