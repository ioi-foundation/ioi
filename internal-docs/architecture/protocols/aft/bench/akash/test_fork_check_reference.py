import unittest
from fork_check_reference import root_agreement

def node(rpc, tip, blocks, reachable=True):
    return {"rpc": rpc, "reachable": reachable, "tip": tip, "blocks": blocks}

A = {h: (f"h{h}", f"r{h}") for h in range(1, 13)}
class T(unittest.TestCase):
    def test_all_agree(self):
        v = root_agreement([node(f"n{i}", 12, A) for i in range(4)])
        self.assertEqual(v["verdict"], "agree"); self.assertEqual(v["common_tip"], 12)
    def test_lagging_node_is_not_a_fork(self):
        lag = {h: A[h] for h in range(1, 11)}
        v = root_agreement([node("n0", 12, A), node("n1", 12, A), node("n2", 12, A), node("n3", 10, lag)])
        self.assertEqual(v["verdict"], "agree"); self.assertEqual(v["common_tip"], 10)
    def test_obs10_shape_is_forked_at_height_11(self):
        B = dict(A); B[11] = ("hB11", "rB11"); B[12] = ("hB12", "rB12")
        majority = {h: A[h] for h in range(1, 12)}          # applied A at 11, cannot apply 12
        v = root_agreement([node("n0", 11, majority), node("n1", 11, majority), node("n2", 11, majority), node("n3", 12, B)])
        self.assertEqual(v["verdict"], "forked"); self.assertEqual(v["first_divergence"]["height"], 11)
    def test_same_hash_different_root_is_forked(self):
        C = dict(A); C[5] = ("h5", "rX")
        v = root_agreement([node("n0", 12, A), node("n1", 12, C)])
        self.assertEqual(v["verdict"], "forked"); self.assertEqual(v["first_divergence"]["height"], 5)
    def test_unreachable_node_is_degraded_never_skipped(self):
        v = root_agreement([node("n0", 12, A), node("n1", None, {}, reachable=False)])
        self.assertEqual(v["verdict"], "degraded")
    def test_missing_block_below_common_tip_is_degraded(self):
        hole = dict(A); del hole[7]
        v = root_agreement([node("n0", 12, A), node("n1", 12, hole)])
        self.assertEqual(v["verdict"], "degraded")
    def test_empty_node_list_is_degraded(self):
        self.assertEqual(root_agreement([])["verdict"], "degraded")
if __name__ == "__main__":
    unittest.main()
