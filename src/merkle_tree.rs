use crate::crypto;

pub struct MerkleTree {
    elements: Vec<MerkleTreeNode>,
}

type MerkleTreeNode = crypto::Hash32;

#[derive(Debug)]
pub struct MerkleTreeLayer {
    elements: Vec<crypto::Hash32>,
}

impl MerkleTree {
    /// Creates a MerkleTree from a vector of Hashable elements
    pub fn new<T: crypto::Hashable>(elts: &Vec<Box<T>>) -> Self {
        let mut elements = Vec::with_capacity(elts.len());
        for elt in elts.iter() {
            elements.push((*elt).hash());
        }
        MerkleTree { elements }
    }

    fn concat(a: &MerkleTreeNode, b: &MerkleTreeNode) -> MerkleTreeNode {
        let mut con = a.to_vec();
        con.extend_from_slice(b);
        crypto::hash32(con.as_slice())
    }

    fn layer_up(elements: Vec<MerkleTreeNode>) -> Vec<MerkleTreeNode> {
        let elements_len = elements.len();
        let end = elements_len / 2;
        let odd = (elements_len % 2) == 1;
        let mut new_elements = Vec::with_capacity(end);
        for i in 0..end {
            new_elements.push(MerkleTree::concat(&elements[i], &elements[i + 1]));
        }
        if odd {
            new_elements.push(MerkleTree::concat(
                &elements[elements_len - 1],
                &elements[elements_len - 1],
            ));
        }
        new_elements
    }

    fn root_rec(elements: Vec<MerkleTreeNode>) -> crypto::Hash32 {
        if elements.len() == 1 {
            return elements[0];
        }

        MerkleTree::root_rec(MerkleTree::layer_up(elements))
    }

    /// Returns the root of the MerkleTree, or None if it's empty
    pub fn root(&self) -> Option<crypto::Hash32> {
        if self.elements.is_empty() {
            return None;
        }

        let elements = self.elements.clone();
        Some(MerkleTree::root_rec(elements))
    }

    /// Returns the height of the MerkleTree (layers numbers)
    pub fn height(&self) -> usize {
        (self.elements.len() as f32).log2().ceil() as usize + 1
    }

    fn dump_rec(
        elements: Vec<MerkleTreeNode>,
        acc: &mut Vec<MerkleTreeLayer>,
    ) -> &Vec<MerkleTreeLayer> {
        if elements.len() == 1 {
            acc.push(MerkleTreeLayer {
                elements: vec![elements[0]],
            });
            return acc;
        }

        let mut vect = Vec::with_capacity(elements.len());
        for elt in elements.iter() {
            vect.push(*elt);
        }
        acc.push(MerkleTreeLayer { elements: vect });

        MerkleTree::dump_rec(MerkleTree::layer_up(elements), acc)
    }

    /// Returns a vector of MerkleTreeLayers, each representing a layer of
    /// the tree. Each layer is made of a vector of hashes.
    /// All vectors are ordered.
    pub fn layers(&self) -> Vec<MerkleTreeLayer> {
        let mut vect = Vec::new();
        let elements = self.elements.clone();
        MerkleTree::dump_rec(elements, &mut vect);
        vect
    }
}

impl std::fmt::Display for MerkleTree {
    /// Print the merkle tree
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MerkleTree:\n")?;
        for (index, layer) in self.layers().iter().enumerate() {
            write!(f, "Layer {} : ", index)?;
            for hash in layer.elements.iter() {
                write!(f, "{} ", hex::encode(hash))?;
            }
            write!(f, "\n")?;
        }
        write!(f, "")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Hashable;

    impl crypto::Hashable for u32 {
        /// Hashable implementation on u32 uses Little Endian
        /// representation and apply hash32
        fn hash(&self) -> crypto::Hash32 {
            crypto::hash32(&self.to_le_bytes())
        }
    }

    #[test]
    fn test_new() {
        let vector: Vec<Box<u32>> = Vec::new();
        let mk = MerkleTree::new(&vector);
        assert_eq!(mk.root(), None);
    }

    #[test]
    fn test_one_elt() {
        let to_insert: u32 = 1;
        // Computed with python
        let to_insert_hash = "41f758f2e5cc078d3795b4fc0cb60c2d735fa92cc020572bdc982dd2d564d11b";
        assert_eq!(hex::decode(to_insert_hash).unwrap(), to_insert.hash());

        let mk = MerkleTree::new(&vec![Box::new(to_insert)]);
        if let Some(hash) = mk.root() {
            assert_eq!(
                hash,
                hex::decode("41f758f2e5cc078d3795b4fc0cb60c2d735fa92cc020572bdc982dd2d564d11b")
                    .unwrap()
                    .as_slice()
            );
        } else {
            panic!();
        }
    }

    #[test]
    fn test_two_elts() {
        let mk = MerkleTree::new(&vec![Box::new(1), Box::new(2)]);
        if let Some(hash) = mk.root() {
            assert_eq!(
                hash,
                hex::decode("494c9c623bffa28edd2211dc1a9d364fd298f2906c85c5f8947e4a6396cf6472")
                    .unwrap()
                    .as_slice()
            );
        } else {
            panic!();
        }
    }

    #[test]
    fn test_three_elts_and_layers() {
        let mk = MerkleTree::new(&vec![Box::new(1), Box::new(2), Box::new(3)]);
        if let Some(hash) = mk.root() {
            assert_eq!(
                hash,
                hex::decode("1225b763f8a06c508bd7c0551c09d090d1e50944ee4bab5b78b7ccd0fa9e4c9f")
                    .unwrap()
                    .as_slice()
            );
        } else {
            panic!();
        }

        let layers = mk.layers();
        assert_eq!(layers[0].elements.len(), 3);
        assert_eq!(
            layers[0].elements[0],
            hex::decode("41f758f2e5cc078d3795b4fc0cb60c2d735fa92cc020572bdc982dd2d564d11b")
                .unwrap()
                .as_slice()
        );

        assert_eq!(
            layers[0].elements[1],
            hex::decode("f9e00e3113f3bfd7653e049d899e5f3c917d020780128ff686e37ce215ab74fe")
                .unwrap()
                .as_slice()
        );
        assert_eq!(
            layers[0].elements[2],
            hex::decode("9953051d0daf36399447027f1ff4ceee27161c808c610b3f961ea3805ab3e793")
                .unwrap()
                .as_slice()
        );

        assert_eq!(layers[1].elements.len(), 2);
        assert_eq!(
            layers[1].elements[0],
            hex::decode("494c9c623bffa28edd2211dc1a9d364fd298f2906c85c5f8947e4a6396cf6472")
                .unwrap()
                .as_slice()
        );
        assert_eq!(
            layers[1].elements[1],
            hex::decode("b1609f84ed2489e94bc3eddc66875f8a38b7aab83c5f9a09875fe41f29132350")
                .unwrap()
                .as_slice()
        );

        assert_eq!(layers[2].elements.len(), 1);
        assert_eq!(
            layers[2].elements[0],
            hex::decode("1225b763f8a06c508bd7c0551c09d090d1e50944ee4bab5b78b7ccd0fa9e4c9f")
                .unwrap()
                .as_slice()
        );
    }

    #[test]
    fn test_height() {
        let mk1 = MerkleTree::new(&vec![
            Box::new(1),
            Box::new(2),
            Box::new(3),
            Box::new(4),
            Box::new(5),
            Box::new(6),
            Box::new(7),
        ]);
        assert_eq!(mk1.height(), 4);
        let mk2 = MerkleTree::new(&vec![
            Box::new(1),
            Box::new(2),
            Box::new(3),
            Box::new(4),
            Box::new(5),
            Box::new(6),
            Box::new(7),
            Box::new(8),
        ]);
        assert_eq!(mk2.height(), 4);
        let mk3 = MerkleTree::new(&vec![
            Box::new(1),
            Box::new(2),
            Box::new(3),
            Box::new(4),
            Box::new(5),
            Box::new(6),
            Box::new(7),
            Box::new(8),
            Box::new(9),
        ]);
        assert_eq!(mk3.height(), 5);
    }
}
