from __future__ import annotations

import unittest

from synvulcommit.run_experiments import build_neural_model, condition_rows, vectorize


class FakeVectors(dict):
    vector_size = 3
    key_to_index = {"safe": 0}


class ExperimentModelTests(unittest.TestCase):
    def test_conditions_reuse_real_validation_and_test_contract(self) -> None:
        real_train, real_validation = [{"id": "rt"}], [{"id": "rv"}]
        synthetic_train, synthetic_validation = [{"id": "st"}], [{"id": "sv"}]
        conditions = condition_rows(real_train, real_validation, synthetic_train, synthetic_validation)
        self.assertIs(conditions["A"][1], real_validation)
        self.assertIs(conditions["C"][1], real_validation)
        self.assertIs(conditions["B"][1], synthetic_validation)
        self.assertEqual([{"id": "rt"}, {"id": "st"}], conditions["C"][0])
    def test_vector_shapes_for_pooled_and_sequence_features(self) -> None:
        try:
            import numpy as np
        except ImportError:
            self.skipTest("NumPy is supplied by the Lab 3 vudenc environment")

        vectors = FakeVectors({"safe": np.array([1, 2, 3], dtype="float32")})
        rows = [{"tokens": ["safe", "missing"], "label": 1}]
        pooled, labels = vectorize(rows, vectors, np, sequence=False)
        sequence, sequence_labels = vectorize(rows, vectors, np, sequence=True)
        self.assertEqual((1, 3), pooled.shape)
        self.assertEqual((1, 200), sequence.shape)
        self.assertEqual(1, sequence[0, 0])
        self.assertEqual([1], labels.tolist())
        self.assertEqual([1], sequence_labels.tolist())

    def test_cpu_smoke_model_builds_when_tensorflow_is_available(self) -> None:
        try:
            import tensorflow as tf
        except ImportError:
            self.skipTest("TensorFlow is supplied by the Lab 3 vudenc environment")
        import numpy as np
        embeddings = np.zeros((2, 300), dtype="float32")
        self.assertEqual((None, 1), build_neural_model("lstm", tf, embeddings).output_shape)
        self.assertEqual((None, 1), build_neural_model("cnn", tf, embeddings).output_shape)


if __name__ == "__main__":
    unittest.main()
