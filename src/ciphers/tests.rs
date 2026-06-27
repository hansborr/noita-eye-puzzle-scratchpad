use super::{
    AglGak, AglGakKey, AglMultiplierSubgroup, AnyCipher, Caesar, CaesarKey, Chaocipher,
    ChaocipherKey, Cipher, CipherError, CosetReadout, DeckCipher, DeckCipherKey,
    EYE_READING_ALPHABET_SIZE, Gak, GakKey, GakKeyOptions, GakSubgroupConstraint, Identity,
    IncrementingWheel, IncrementingWheelKey, Transposition, TranspositionKey, Vigenere,
    VigenereKey, agl_apply, agl_compose, agl_gak_decrypt, agl_gak_encrypt, caesar_decrypt,
    caesar_encrypt, chaocipher_decrypt, chaocipher_encrypt, deck_cipher_decrypt,
    deck_cipher_encrypt, gak_decrypt, gak_encrypt, identity_decrypt, identity_encrypt,
    incrementing_wheel_decrypt, incrementing_wheel_encrypt, transposition_decrypt,
    transposition_encrypt, vigenere_decrypt, vigenere_encrypt,
};
use crate::analysis::isomorph::PatternSignature;
use crate::core::glyph::Glyph;
use crate::nulls::null::SplitMix64;

#[test]
fn identity_cipher_passes_through_and_trait_matches_free_functions() {
    let cipher = Identity;
    let plaintext = glyphs(&[4, 1, 3, 1, 0]);
    let ciphertext = identity_encrypt(&plaintext).unwrap();

    assert_eq!(cipher.name(), "identity");
    assert_eq!(ciphertext, plaintext);
    assert_eq!(cipher.encrypt(&(), &plaintext).unwrap(), ciphertext);
    assert_eq!(
        cipher.decrypt(&(), &ciphertext).unwrap(),
        identity_decrypt(&ciphertext).unwrap()
    );
}

#[test]
fn transposition_known_tiny_vector_and_trait_matches_free_functions() {
    let cipher = Transposition;
    let key = TranspositionKey::new(4, vec![2, 0, 3, 1]).unwrap();
    let plaintext = glyphs(&[0, 1, 2, 3, 4, 5, 6]);
    let ciphertext = transposition_encrypt(&plaintext, &key).unwrap();

    assert_eq!(values(&ciphertext), vec![1, 3, 0, 2, 5, 4, 6]);
    assert_eq!(transposition_decrypt(&ciphertext, &key).unwrap(), plaintext);
    assert_eq!(cipher.name(), "transposition");
    assert_eq!(cipher.encrypt(&key, &plaintext).unwrap(), ciphertext);
    assert_eq!(
        cipher.decrypt(&key, &ciphertext).unwrap(),
        transposition_decrypt(&ciphertext, &key).unwrap()
    );
}

#[test]
fn caesar_known_tiny_vector() {
    let key = CaesarKey::new(5, 2).unwrap();
    let plaintext = glyphs(&[0, 1, 4]);
    let ciphertext = caesar_encrypt(&plaintext, &key).unwrap();
    assert_eq!(values(&ciphertext), vec![2, 3, 1]);
    assert_eq!(caesar_decrypt(&ciphertext, &key).unwrap(), plaintext);
}

#[test]
fn caesar_trait_matches_free_functions() {
    let cipher = Caesar;
    let key = CaesarKey::new(5, 2).unwrap();
    let plaintext = glyphs(&[0, 1, 4]);
    let ciphertext = caesar_encrypt(&plaintext, &key).unwrap();

    assert_eq!(cipher.name(), "Caesar");
    assert_eq!(cipher.encrypt(&key, &plaintext).unwrap(), ciphertext);
    assert_eq!(
        cipher.decrypt(&key, &ciphertext).unwrap(),
        caesar_decrypt(&ciphertext, &key).unwrap()
    );
}

#[test]
fn vigenere_known_tiny_vector() {
    let key = VigenereKey::new(5, vec![1, 0, 3]).unwrap();
    let plaintext = glyphs(&[0, 4, 2, 3]);
    let ciphertext = vigenere_encrypt(&plaintext, &key).unwrap();
    assert_eq!(values(&ciphertext), vec![1, 4, 0, 4]);
    assert_eq!(vigenere_decrypt(&ciphertext, &key).unwrap(), plaintext);
}

#[test]
fn vigenere_trait_matches_free_functions() {
    let cipher = Vigenere;
    let key = VigenereKey::new(5, vec![1, 0, 3]).unwrap();
    let plaintext = glyphs(&[0, 4, 2, 3]);
    let ciphertext = vigenere_encrypt(&plaintext, &key).unwrap();

    assert_eq!(cipher.name(), "Vigenere");
    assert_eq!(cipher.encrypt(&key, &plaintext).unwrap(), ciphertext);
    assert_eq!(
        cipher.decrypt(&key, &ciphertext).unwrap(),
        vigenere_decrypt(&ciphertext, &key).unwrap()
    );
}

#[test]
fn incrementing_wheel_known_tiny_vector() {
    let key = IncrementingWheelKey::new(5, 1, 2).unwrap();
    let plaintext = glyphs(&[0, 1, 2, 3]);
    let ciphertext = incrementing_wheel_encrypt(&plaintext, &key).unwrap();
    assert_eq!(values(&ciphertext), vec![1, 4, 2, 0]);
    assert_eq!(
        incrementing_wheel_decrypt(&ciphertext, &key).unwrap(),
        plaintext
    );
}

#[test]
fn incrementing_wheel_trait_matches_free_functions() {
    let cipher = IncrementingWheel;
    let key = IncrementingWheelKey::new(5, 1, 2).unwrap();
    let plaintext = glyphs(&[0, 1, 2, 3]);
    let ciphertext = incrementing_wheel_encrypt(&plaintext, &key).unwrap();

    assert_eq!(cipher.name(), "incrementing-wheel");
    assert_eq!(cipher.encrypt(&key, &plaintext).unwrap(), ciphertext);
    assert_eq!(
        cipher.decrypt(&key, &ciphertext).unwrap(),
        incrementing_wheel_decrypt(&ciphertext, &key).unwrap()
    );
}

#[test]
fn chaocipher_known_tiny_vector() {
    let key = ChaocipherKey::identity(7).unwrap();
    let plaintext = glyphs(&[0, 2, 4, 6]);
    let ciphertext = chaocipher_encrypt(&plaintext, &key).unwrap();
    assert_eq!(values(&ciphertext), vec![0, 2, 2, 4]);
    assert_eq!(chaocipher_decrypt(&ciphertext, &key).unwrap(), plaintext);
}

#[test]
fn chaocipher_trait_matches_free_functions() {
    let cipher = Chaocipher;
    let key = ChaocipherKey::identity(7).unwrap();
    let plaintext = glyphs(&[0, 2, 4, 6]);
    let ciphertext = chaocipher_encrypt(&plaintext, &key).unwrap();

    assert_eq!(cipher.name(), "Chaocipher");
    assert_eq!(cipher.encrypt(&key, &plaintext).unwrap(), ciphertext);
    assert_eq!(
        cipher.decrypt(&key, &ciphertext).unwrap(),
        chaocipher_decrypt(&ciphertext, &key).unwrap()
    );
}

#[test]
fn chaocipher_matches_classic_published_vector() {
    let left = alphabet("HXUCZVAMDSLKPEFJRIGTWOBNYQ");
    let right = alphabet("PTLNBQDEOYSFAVZKGJRIHWXUMC");
    let key = ChaocipherKey::new(26, left, right).unwrap();
    let plaintext = alphabet("WELLDONEISBETTERTHANWELLSAID");
    let ciphertext = chaocipher_encrypt(&glyphs_from_usize(&plaintext), &key).unwrap();
    assert_eq!(letters(&ciphertext), "OAHQHCNYNXTSZJRRHJBYHQKSOUJY");
    assert_eq!(
        chaocipher_decrypt(&ciphertext, &key).unwrap(),
        glyphs_from_usize(&plaintext)
    );
}

#[test]
fn deck_cipher_known_tiny_vector() {
    let key = DeckCipherKey::identity(5).unwrap();
    let plaintext = glyphs(&[0, 0, 0, 0]);
    let ciphertext = deck_cipher_encrypt(&plaintext, &key).unwrap();
    assert_eq!(values(&ciphertext), vec![3, 0, 3, 0]);
    assert_eq!(deck_cipher_decrypt(&ciphertext, &key).unwrap(), plaintext);
}

#[test]
fn deck_cipher_trait_matches_free_functions() {
    let cipher = DeckCipher;
    let key = DeckCipherKey::identity(5).unwrap();
    let plaintext = glyphs(&[0, 0, 0, 0]);
    let ciphertext = deck_cipher_encrypt(&plaintext, &key).unwrap();

    assert_eq!(cipher.name(), "deck");
    assert_eq!(cipher.encrypt(&key, &plaintext).unwrap(), ciphertext);
    assert_eq!(
        cipher.decrypt(&key, &ciphertext).unwrap(),
        deck_cipher_decrypt(&ciphertext, &key).unwrap()
    );
}

#[test]
fn agl_gak_matches_hand_computed_n5() {
    let key = AglGakKey::new(
        5,
        AglMultiplierSubgroup::Full,
        0,
        (1, 0),
        vec![(1, 1), (1, 2), (2, 0)],
    )
    .unwrap();

    let first_plaintext = glyphs(&[0, 0]);
    let first_ciphertext = agl_gak_encrypt(&first_plaintext, &key).unwrap();
    assert_eq!(values(&first_ciphertext), vec![1, 2]);
    assert_eq!(
        agl_gak_decrypt(&first_ciphertext, &key).unwrap(),
        first_plaintext
    );

    let second_plaintext = glyphs(&[2, 0]);
    let second_ciphertext = agl_gak_encrypt(&second_plaintext, &key).unwrap();
    assert_eq!(values(&second_ciphertext), vec![0, 2]);
    assert_eq!(
        agl_gak_decrypt(&second_ciphertext, &key).unwrap(),
        second_plaintext
    );
}

#[test]
fn agl_gak_trait_matches_free_functions() {
    let cipher = AglGak;
    let key = AglGakKey::new(
        5,
        AglMultiplierSubgroup::Full,
        0,
        (1, 0),
        vec![(1, 1), (1, 2), (2, 0)],
    )
    .unwrap();
    let plaintext = glyphs(&[2, 0]);
    let ciphertext = agl_gak_encrypt(&plaintext, &key).unwrap();

    assert_eq!(cipher.name(), "AGL-GAK");
    assert_eq!(cipher.encrypt(&key, &plaintext).unwrap(), ciphertext);
    assert_eq!(
        cipher.decrypt(&key, &ciphertext).unwrap(),
        agl_gak_decrypt(&ciphertext, &key).unwrap()
    );
}

#[test]
fn agl_gak_wrong_left_update_convention_differs() {
    let key = AglGakKey::new(
        5,
        AglMultiplierSubgroup::Full,
        0,
        (1, 0),
        vec![(1, 1), (1, 2), (2, 0)],
    )
    .unwrap();
    let plaintext = glyphs(&[2, 0]);
    let right_update = agl_gak_encrypt(&plaintext, &key).unwrap();
    let wrong_left_update = wrong_left_update_encrypt(&plaintext, &key);
    assert_eq!(values(&right_update), vec![0, 2]);
    assert_eq!(wrong_left_update, vec![0, 1]);
    assert_ne!(values(&right_update), wrong_left_update);
}

#[test]
fn caesar_round_trips_random_plaintexts() {
    let small_keys = [
        CaesarKey::new(7, 0).unwrap(),
        CaesarKey::new(7, 19).unwrap(),
    ];
    let eye_keys = [
        CaesarKey::new(EYE_READING_ALPHABET_SIZE, 1).unwrap(),
        CaesarKey::new(EYE_READING_ALPHABET_SIZE, 82).unwrap(),
    ];
    for (index, key) in small_keys.iter().chain(eye_keys.iter()).enumerate() {
        let plaintext = random_plaintext(0x6361_6573_6172 ^ index as u64, 257, key.alphabet_size());
        let ciphertext = caesar_encrypt(&plaintext, key).unwrap();
        assert_eq!(caesar_decrypt(&ciphertext, key).unwrap(), plaintext);
    }
}

#[test]
fn transposition_round_trips_random_plaintexts() {
    let keys = [
        TranspositionKey::new(1, vec![0]).unwrap(),
        TranspositionKey::new(4, vec![2, 0, 3, 1]).unwrap(),
        TranspositionKey::new(7, vec![3, 0, 6, 1, 5, 2, 4]).unwrap(),
    ];
    for (index, key) in keys.iter().enumerate() {
        let plaintext = random_plaintext(0x7472_616e_7370 ^ index as u64, 263, 11);
        let ciphertext = transposition_encrypt(&plaintext, key).unwrap();
        assert_eq!(transposition_decrypt(&ciphertext, key).unwrap(), plaintext);
    }
}

#[test]
fn vigenere_round_trips_random_plaintexts() {
    let small_keys = [
        VigenereKey::new(7, vec![0]).unwrap(),
        VigenereKey::new(7, vec![1, 3, 6, 2]).unwrap(),
    ];
    let eye_keys = [
        VigenereKey::new(EYE_READING_ALPHABET_SIZE, vec![0, 1, 82]).unwrap(),
        VigenereKey::new(EYE_READING_ALPHABET_SIZE, vec![5, 17, 29, 41, 80]).unwrap(),
    ];
    for (index, key) in small_keys.iter().chain(eye_keys.iter()).enumerate() {
        let plaintext = random_plaintext(0x7669_6765_6e65 ^ index as u64, 313, key.alphabet_size());
        let ciphertext = vigenere_encrypt(&plaintext, key).unwrap();
        assert_eq!(vigenere_decrypt(&ciphertext, key).unwrap(), plaintext);
    }
}

#[test]
fn incrementing_wheel_round_trips_random_plaintexts() {
    let small_keys = [
        IncrementingWheelKey::new(7, 0, 1).unwrap(),
        IncrementingWheelKey::new(7, 3, 5).unwrap(),
    ];
    let eye_keys = [
        IncrementingWheelKey::new(EYE_READING_ALPHABET_SIZE, 0, 1).unwrap(),
        IncrementingWheelKey::new(EYE_READING_ALPHABET_SIZE, 19, 37).unwrap(),
    ];
    for (index, key) in small_keys.iter().chain(eye_keys.iter()).enumerate() {
        let plaintext = random_plaintext(0x7768_6565_6c21 ^ index as u64, 331, key.alphabet_size());
        let ciphertext = incrementing_wheel_encrypt(&plaintext, key).unwrap();
        assert_eq!(
            incrementing_wheel_decrypt(&ciphertext, key).unwrap(),
            plaintext
        );
    }
}

#[test]
fn chaocipher_round_trips_random_plaintexts() {
    let small_keys = [
        ChaocipherKey::identity(7).unwrap(),
        ChaocipherKey::new(7, vec![3, 1, 6, 0, 5, 2, 4], vec![2, 4, 0, 6, 1, 5, 3]).unwrap(),
    ];
    let eye_keys = [
        ChaocipherKey::identity(EYE_READING_ALPHABET_SIZE).unwrap(),
        ChaocipherKey::new(
            EYE_READING_ALPHABET_SIZE,
            shuffled_permutation(EYE_READING_ALPHABET_SIZE, 0x0063_6861_6f6c),
            shuffled_permutation(EYE_READING_ALPHABET_SIZE, 0x0063_6861_6f72),
        )
        .unwrap(),
    ];
    for (index, key) in small_keys.iter().chain(eye_keys.iter()).enumerate() {
        let plaintext = random_plaintext(0x6368_616f_2121 ^ index as u64, 211, key.alphabet_size());
        let ciphertext = chaocipher_encrypt(&plaintext, key).unwrap();
        assert_eq!(chaocipher_decrypt(&ciphertext, key).unwrap(), plaintext);
    }
}

#[test]
fn deck_cipher_round_trips_random_plaintexts() {
    let small_keys = [
        DeckCipherKey::identity(7).unwrap(),
        DeckCipherKey::new(7, vec![3, 1, 6, 0, 5, 2, 4], 5, 2).unwrap(),
    ];
    let eye_keys = [
        DeckCipherKey::identity(EYE_READING_ALPHABET_SIZE).unwrap(),
        DeckCipherKey::new(
            EYE_READING_ALPHABET_SIZE,
            shuffled_permutation(EYE_READING_ALPHABET_SIZE, 0x0064_6563_6b83),
            17,
            80,
        )
        .unwrap(),
    ];
    for (index, key) in small_keys.iter().chain(eye_keys.iter()).enumerate() {
        let plaintext = random_plaintext(0x6465_636b_2121 ^ index as u64, 233, key.alphabet_size());
        let ciphertext = deck_cipher_encrypt(&plaintext, key).unwrap();
        assert_eq!(deck_cipher_decrypt(&ciphertext, key).unwrap(), plaintext);
    }
}

#[test]
fn agl_gak_round_trips_random_plaintexts() {
    let keys = [
        AglGakKey::identity(7, AglMultiplierSubgroup::Full).unwrap(),
        AglGakKey::identity(7, AglMultiplierSubgroup::QuadraticResidues).unwrap(),
        AglGakKey::new(
            7,
            AglMultiplierSubgroup::Full,
            0,
            (3, 4),
            vec![(1, 0), (2, 1), (3, 2), (4, 3), (5, 4), (6, 5), (1, 6)],
        )
        .unwrap(),
        AglGakKey::identity(EYE_READING_ALPHABET_SIZE, AglMultiplierSubgroup::Full).unwrap(),
        AglGakKey::identity(
            EYE_READING_ALPHABET_SIZE,
            AglMultiplierSubgroup::QuadraticResidues,
        )
        .unwrap(),
    ];
    for (index, key) in keys.iter().enumerate() {
        let plaintext = random_plaintext(
            0x6167_6c5f_6761_6b21 ^ index as u64,
            271,
            key.letter_elements().len(),
        );
        let ciphertext = agl_gak_encrypt(&plaintext, key).unwrap();
        assert_eq!(agl_gak_decrypt(&ciphertext, key).unwrap(), plaintext);
    }
}

#[test]
fn gak_round_trips_random_plaintexts_small_and_eye() {
    // Deck-realization (S_n, hidden subgroup S_{n-1}) GAK keys: one random
    // small permutation per plaintext letter, then the full 83-symbol size.
    let small_letters = random_distinct_coset_letters(7, 7, 0x6761_6b5f_736d);
    let eye_letters = random_distinct_coset_letters(
        EYE_READING_ALPHABET_SIZE,
        EYE_READING_ALPHABET_SIZE,
        0x6761_6b5f_6579,
    );
    let keys = [
        GakKey::deck(7, small_letters, GakKeyOptions::default()).unwrap(),
        GakKey::deck(
            EYE_READING_ALPHABET_SIZE,
            eye_letters,
            GakKeyOptions::default(),
        )
        .unwrap(),
    ];
    for (index, key) in keys.iter().enumerate() {
        let plaintext = random_plaintext(
            0x6761_6b5f_7274 ^ index as u64,
            277,
            key.plaintext_letters().len(),
        );
        let ciphertext = gak_encrypt(&plaintext, key).unwrap();
        assert_eq!(gak_decrypt(&ciphertext, key).unwrap(), plaintext);
    }
}

#[test]
fn gak_trait_matches_free_functions() {
    let cipher = Gak;
    let n = 5usize;
    let letters = (0..n).map(|shift| rotation_permutation(n, shift)).collect();
    let key = GakKey::deck(n, letters, GakKeyOptions::default()).unwrap();
    let plaintext = glyphs(&[0, 1, 4, 2]);
    let ciphertext = gak_encrypt(&plaintext, &key).unwrap();

    assert_eq!(cipher.name(), "GAK");
    assert_eq!(cipher.encrypt(&key, &plaintext).unwrap(), ciphertext);
    assert_eq!(
        cipher.decrypt(&key, &ciphertext).unwrap(),
        gak_decrypt(&ciphertext, &key).unwrap()
    );
}

#[test]
fn any_cipher_caesar_matches_free_functions_and_round_trips() {
    let key = CaesarKey::new(5, 2).unwrap();
    let plaintext = glyphs(&[0, 1, 4]);
    let expected = caesar_encrypt(&plaintext, &key).unwrap();
    let cipher = AnyCipher::Caesar(key);

    let ciphertext = cipher.encrypt(&plaintext).unwrap();
    assert_eq!(cipher.name(), "Caesar");
    assert_eq!(ciphertext, expected);
    assert_eq!(cipher.decrypt(&ciphertext).unwrap(), plaintext);
}

#[test]
fn any_cipher_identity_matches_free_functions_and_round_trips() {
    let plaintext = glyphs(&[0, 4, 2, 3]);
    let expected = identity_encrypt(&plaintext).unwrap();
    let cipher = AnyCipher::Identity;

    let ciphertext = cipher.encrypt(&plaintext).unwrap();
    assert_eq!(cipher.name(), "identity");
    assert_eq!(ciphertext, expected);
    assert_eq!(cipher.decrypt(&ciphertext).unwrap(), plaintext);
}

#[test]
fn any_cipher_transposition_matches_free_functions_and_round_trips() {
    let key = TranspositionKey::new(3, vec![1, 2, 0]).unwrap();
    let plaintext = glyphs(&[0, 1, 2, 3, 4]);
    let expected = transposition_encrypt(&plaintext, &key).unwrap();
    let cipher = AnyCipher::Transposition(key);

    let ciphertext = cipher.encrypt(&plaintext).unwrap();
    assert_eq!(cipher.name(), "transposition");
    assert_eq!(ciphertext, expected);
    assert_eq!(cipher.decrypt(&ciphertext).unwrap(), plaintext);
}

#[test]
fn any_cipher_vigenere_matches_free_functions_and_round_trips() {
    let key = VigenereKey::new(5, vec![1, 0, 3]).unwrap();
    let plaintext = glyphs(&[0, 4, 2, 3]);
    let expected = vigenere_encrypt(&plaintext, &key).unwrap();
    let cipher = AnyCipher::Vigenere(key);

    let ciphertext = cipher.encrypt(&plaintext).unwrap();
    assert_eq!(cipher.name(), "Vigenere");
    assert_eq!(ciphertext, expected);
    assert_eq!(cipher.decrypt(&ciphertext).unwrap(), plaintext);
}

#[test]
fn any_cipher_incrementing_wheel_matches_free_functions_and_round_trips() {
    let key = IncrementingWheelKey::new(5, 1, 2).unwrap();
    let plaintext = glyphs(&[0, 1, 2, 3]);
    let expected = incrementing_wheel_encrypt(&plaintext, &key).unwrap();
    let cipher = AnyCipher::IncrementingWheel(key);

    let ciphertext = cipher.encrypt(&plaintext).unwrap();
    assert_eq!(cipher.name(), "incrementing-wheel");
    assert_eq!(ciphertext, expected);
    assert_eq!(cipher.decrypt(&ciphertext).unwrap(), plaintext);
}

#[test]
fn any_cipher_chaocipher_matches_free_functions_and_round_trips() {
    let key = ChaocipherKey::identity(7).unwrap();
    let plaintext = glyphs(&[0, 2, 4, 6]);
    let expected = chaocipher_encrypt(&plaintext, &key).unwrap();
    let cipher = AnyCipher::Chaocipher(key);

    let ciphertext = cipher.encrypt(&plaintext).unwrap();
    assert_eq!(cipher.name(), "Chaocipher");
    assert_eq!(ciphertext, expected);
    assert_eq!(cipher.decrypt(&ciphertext).unwrap(), plaintext);
}

#[test]
fn any_cipher_deck_cipher_matches_free_functions_and_round_trips() {
    let key = DeckCipherKey::identity(5).unwrap();
    let plaintext = glyphs(&[0, 0, 0, 0]);
    let expected = deck_cipher_encrypt(&plaintext, &key).unwrap();
    let cipher = AnyCipher::DeckCipher(key);

    let ciphertext = cipher.encrypt(&plaintext).unwrap();
    assert_eq!(cipher.name(), "deck");
    assert_eq!(ciphertext, expected);
    assert_eq!(cipher.decrypt(&ciphertext).unwrap(), plaintext);
}

#[test]
fn any_cipher_agl_gak_matches_free_functions_and_round_trips() {
    let key = AglGakKey::new(
        5,
        AglMultiplierSubgroup::Full,
        0,
        (1, 0),
        vec![(1, 1), (1, 2), (2, 0)],
    )
    .unwrap();
    let plaintext = glyphs(&[2, 0]);
    let expected = agl_gak_encrypt(&plaintext, &key).unwrap();
    let cipher = AnyCipher::AglGak(key);

    let ciphertext = cipher.encrypt(&plaintext).unwrap();
    assert_eq!(cipher.name(), "AGL-GAK");
    assert_eq!(ciphertext, expected);
    assert_eq!(cipher.decrypt(&ciphertext).unwrap(), plaintext);
}

#[test]
fn any_cipher_gak_matches_free_functions_and_round_trips() {
    let n = 5usize;
    let letters: Vec<Vec<usize>> = (0..n).map(|shift| rotation_permutation(n, shift)).collect();
    let key = GakKey::deck(n, letters, GakKeyOptions::default()).unwrap();
    let plaintext = glyphs(&[0, 1, 4, 2]);
    let expected = gak_encrypt(&plaintext, &key).unwrap();
    let cipher = AnyCipher::Gak(key);

    let ciphertext = cipher.encrypt(&plaintext).unwrap();
    assert_eq!(cipher.name(), "GAK");
    assert_eq!(ciphertext, expected);
    assert_eq!(cipher.decrypt(&ciphertext).unwrap(), plaintext);
}

#[test]
fn gak_reduces_to_gctak_when_hidden_subgroup_trivial() {
    // Cyclic state group C_n realized as rotation permutations on 0..n with a
    // bijective TopCard readout: H is trivial, so GAK must equal GCTAK. The
    // independent reference is the cumulative-shift autokey on the rotation
    // amounts.
    let n = 11usize;
    let shifts = [0usize, 1, 3, 5, 7, 9, 2, 4, 6, 8, 10];
    let letters: Vec<Vec<usize>> = shifts.iter().map(|&s| rotation_permutation(n, s)).collect();
    let key = GakKey::deck(n, letters, GakKeyOptions::default()).unwrap();

    let plaintext = random_plaintext(0x6763_7461_6b21, 191, shifts.len());
    let ciphertext = gak_encrypt(&plaintext, &key).unwrap();
    let reference = gctak_rotation_reference(&plaintext, &shifts, n);
    assert_eq!(values(&ciphertext), reference);
    assert_eq!(gak_decrypt(&ciphertext, &key).unwrap(), plaintext);
}

#[test]
fn gak_preserves_isomorph_pattern_on_repeated_phrase() {
    // A plaintext with a repeated phrase must produce ciphertext windows
    // whose first-occurrence equality patterns are identical at the repeats:
    // the perfect-isomorph signal the attack needs to bite on.
    let letters = random_distinct_coset_letters(7, 7, 0x6973_6f5f_6761);
    let key = GakKey::deck(7, letters, GakKeyOptions::default()).unwrap();

    let phrase = [1usize, 4, 1, 0, 3, 4];
    let mut plaintext_values = Vec::new();
    plaintext_values.extend_from_slice(&phrase);
    plaintext_values.extend_from_slice(&[2, 5, 0]);
    let first_start = plaintext_values.len();
    plaintext_values.extend_from_slice(&phrase);
    let plaintext = glyphs_from_usize(&plaintext_values);

    let ciphertext = gak_encrypt(&plaintext, &key).unwrap();
    let ct_owned = values_usize(&ciphertext);
    let ct_values: &[usize] = &ct_owned;

    // Both occurrences have length `phrase.len()`; fetch each via the
    // windows iterator so no range indexing is needed.
    let mut windows = ct_values.windows(phrase.len());
    let first_window = windows.next().unwrap();
    let first_signature = PatternSignature::from_window(first_window);
    let second_window = windows.nth(first_start - 1).unwrap();
    let second_signature = PatternSignature::from_window(second_window);
    assert_eq!(first_signature, second_signature);
    // Proving the *ciphertext* reproduces the isomorph: the CT window's own
    // first-occurrence pattern must be non-trivial (have a repeated symbol),
    // otherwise two all-distinct CT windows would also pass the equality
    // above without any isomorph being carried into the ciphertext. The
    // first/second signatures are equal, so checking either suffices.
    assert!(
        first_signature.has_repeated_symbol(),
        "ciphertext window {first_window:?} is all-distinct, so no isomorph is reproduced"
    );
}

#[test]
fn gak_avoid_doubles_forbids_adjacent_equal_ciphertext() {
    // Surviving letters (rotations by 1..n, none in the identity coset)
    // never repeat a ciphertext symbol back-to-back under avoid_doubles.
    let n = 7usize;
    let letters: Vec<Vec<usize>> = (1..n).map(|s| rotation_permutation(n, s)).collect();
    let key = GakKey::deck(n, letters, avoid_doubles_options()).unwrap();

    let plaintext = random_plaintext(0x6e6f_5f64_626c, 211, key.plaintext_letters().len());
    let ciphertext = gak_encrypt(&plaintext, &key).unwrap();
    let ct_values = values_usize(&ciphertext);
    for pair in ct_values.windows(2) {
        if let [a, b] = pair {
            assert_ne!(a, b, "avoid_doubles produced adjacent-equal ciphertext");
        }
    }
    assert_eq!(gak_decrypt(&ciphertext, &key).unwrap(), plaintext);
}

#[test]
fn gak_avoid_doubles_rejects_letter_in_identity_coset() {
    // The identity permutation (rotation by 0) fixes the readout coset of
    // the identity initial state, so avoid_doubles must reject it at
    // construction rather than silently allowing adjacent-equal ciphertext.
    let n = 7usize;
    // Pair the identity letter with a non-identity rotation so the only
    // failure cause is the identity-coset rule, not coset collision.
    let letters = vec![rotation_permutation(n, 0), rotation_permutation(n, 3)];
    let error = GakKey::deck(n, letters, avoid_doubles_options()).unwrap_err();
    // rotation(7,0) is the identity; its TopCard readout p^{-1}[0] = 0,
    // the base coset, so letter 0 is the offender.
    assert!(matches!(
        error,
        CipherError::GakLetterFixesCoset {
            letter_index: 0,
            coset: 0,
        }
    ));
}

#[test]
fn gak_rejects_letters_sharing_a_coset() {
    // Two DISTINCT plaintext letters whose TopCard image (the position of
    // card 0) coincides collide on the same coset from the identity state,
    // so construction must fail (no panic). Both place card 0 at index 2 but
    // differ elsewhere, so this is a genuine coset collision, not equality.
    let n = 5usize;
    let letter_a = vec![1usize, 3, 0, 4, 2];
    let letter_b = vec![4usize, 1, 0, 2, 3];
    assert_ne!(letter_a, letter_b, "letters must be distinct permutations");
    let letters = vec![letter_a, letter_b];
    let error = GakKey::deck(n, letters, GakKeyOptions::default()).unwrap_err();
    // Under left-update p ∘ identity = p, the readout p^{-1}[0] = 2 for both.
    assert!(matches!(
        error,
        CipherError::GakLettersShareCoset {
            coset: 2,
            duplicate_index: 1,
        }
    ));
}

#[test]
fn gak_rejects_non_permutation_letter() {
    // A malformed letter (repeats symbol 0, omits 4) is caught by the shared
    // validate_permutation helper rather than silently accepted.
    let n = 5usize;
    let letters = vec![vec![0usize, 1, 2, 3, 0]];
    let error = GakKey::deck(n, letters, GakKeyOptions::default()).unwrap_err();
    assert!(matches!(
        error,
        CipherError::DuplicatePermutationSymbol {
            label: "GAK plaintext letter",
            symbol: 0,
            ..
        }
    ));
}

#[test]
fn gak_alternating_subgroup_rejects_odd_permutation() {
    // A single transposition is odd, so the A_n parity constraint rejects it.
    let n = 5usize;
    let mut odd = identity_usize(n);
    odd.swap(0, 1);
    let options = GakKeyOptions {
        avoid_doubles: false,
        subgroup: GakSubgroupConstraint::AlternatingGroup,
    };
    let error = GakKey::deck(n, vec![odd], options).unwrap_err();
    assert!(matches!(
        error,
        CipherError::GakLetterWrongParity { letter_index: 0 }
    ));
}

#[test]
fn gak_round_trips_accepted_coset_table_key() {
    // A genuine, *coarser* right-coset projection of the Klein four-group
    // V_4 = {id, a, b, ab} on 0..4, hidden subgroup H = {id, a}. The cosets
    // are H (card-0 positions 0,1) and Hb (positions 2,3), so the projection
    // coset_of = [0,0,1,1] merges pairs and emits only |C| = 2 symbols. This
    // is a valid key the new reachable-state validator must accept and that
    // must round-trip exactly.
    let n = 4usize;
    let a = vec![1usize, 0, 3, 2]; // (0 1)(2 3)
    let b = vec![2usize, 3, 0, 1]; // (0 2)(1 3)
    let readout = CosetReadout::CosetTable {
        reference_value: 0,
        coset_of: vec![0usize, 0, 1, 1],
    };
    let key = GakKey::new(
        n,
        vec![a, b],
        identity_usize(n),
        readout,
        GakKeyOptions::default(),
    )
    .unwrap();
    assert_eq!(key.ciphertext_alphabet_size(), 2);

    let plaintext = random_plaintext(0x636f_7365_7421, 233, key.plaintext_letters().len());
    let ciphertext = gak_encrypt(&plaintext, &key).unwrap();
    assert_eq!(gak_decrypt(&ciphertext, &key).unwrap(), plaintext);
}

#[test]
fn gak_round_trips_non_identity_initial_state() {
    // Non-identity initial state g_0 = rot(5,2) with rotation letters whose
    // readouts from g_0 are distinct; decrypt replays the same g_0.
    let n = 5usize;
    let initial = rotation_permutation(n, 2);
    let letters: Vec<Vec<usize>> = (1..n).map(|s| rotation_permutation(n, s)).collect();
    let key = GakKey::new(
        n,
        letters,
        initial,
        CosetReadout::TopCard { reference_value: 0 },
        GakKeyOptions::default(),
    )
    .unwrap();

    let plaintext = random_plaintext(0x6e6f_6e69_6432, 199, key.plaintext_letters().len());
    let ciphertext = gak_encrypt(&plaintext, &key).unwrap();
    assert_eq!(gak_decrypt(&ciphertext, &key).unwrap(), plaintext);
}

#[test]
fn gak_round_trips_alternating_subgroup_key() {
    // Four even permutations of 0..4 (A_4) with distinct card-0 positions, so
    // the parity constraint accepts them and the coset readouts are distinct.
    let n = 4usize;
    let letters = vec![
        identity_usize(n),
        vec![1usize, 0, 3, 2],
        vec![1usize, 2, 0, 3],
        vec![1usize, 3, 2, 0],
    ];
    let options = GakKeyOptions {
        avoid_doubles: false,
        subgroup: GakSubgroupConstraint::AlternatingGroup,
    };
    let key = GakKey::deck(n, letters, options).unwrap();

    let plaintext = random_plaintext(0x615f_6e5f_6b65_7921, 223, key.plaintext_letters().len());
    let ciphertext = gak_encrypt(&plaintext, &key).unwrap();
    assert_eq!(gak_decrypt(&ciphertext, &key).unwrap(), plaintext);
}

#[test]
fn gak_rejects_non_invertible_coset_table() {
    // P0 regression. n=3, CosetTable{ref 0, coset_of [0,1,1]}, letters
    // id=[0,1,2] and q=[2,0,1]. From the identity state the two letters land
    // in distinct cosets (0 and 1), so the cheap identity-only check passes;
    // but plaintexts [1,0] and [1,1] both encrypt to [1,1], so the key is NOT
    // invertible. The reachable-state validator must reject it: from state
    // [2,0,1] both letters project to coset 1.
    let n = 3usize;
    let letters = vec![vec![0usize, 1, 2], vec![2usize, 0, 1]];
    let readout = CosetReadout::CosetTable {
        reference_value: 0,
        coset_of: vec![0usize, 1, 1],
    };
    let error = GakKey::new(
        n,
        letters,
        identity_usize(n),
        readout,
        GakKeyOptions::default(),
    )
    .unwrap_err();
    assert!(
        matches!(
            error,
            CipherError::GakCosetTableNotInvertible {
                coset: 1,
                duplicate_index: 1,
                ..
            }
        ),
        "expected GakCosetTableNotInvertible, got {error:?}"
    );
}

#[test]
fn gak_rejects_oversize_coset_table() {
    // P1 regression. A coset label too large to encode as a Glyph (and to
    // allocate a seen-cosets table for) must be rejected at construction,
    // not allowed to reach an impossible allocation or a non-encodable
    // emitted symbol.
    let n = 3usize;
    let readout = CosetReadout::CosetTable {
        reference_value: 0,
        coset_of: vec![0usize, 1, usize::MAX - 1],
    };
    let error = GakKey::new(
        n,
        vec![identity_usize(n)],
        identity_usize(n),
        readout,
        GakKeyOptions::default(),
    )
    .unwrap_err();
    assert!(
        matches!(error, CipherError::GakReadoutCosetOutsideAlphabet { .. }),
        "expected GakReadoutCosetOutsideAlphabet, got {error:?}"
    );
}

fn rotation_permutation(n: usize, shift: usize) -> Vec<usize> {
    (0..n).map(|i| (i + shift) % n).collect()
}

fn identity_usize(n: usize) -> Vec<usize> {
    (0..n).collect()
}

fn avoid_doubles_options() -> GakKeyOptions {
    GakKeyOptions {
        avoid_doubles: true,
        subgroup: GakSubgroupConstraint::SymmetricGroup,
    }
}

fn gctak_rotation_reference(plaintext: &[Glyph], shifts: &[usize], n: usize) -> Vec<u16> {
    // Independent reference: under left-update g <- rot(s) o g from identity,
    // the cumulative state is rot(S) with S the running shift-sum, and the
    // inverse-image readout g^{-1}[0] is the position holding card 0, i.e.
    // (n - S) mod n. This is a bijection of S, so it is a valid GCTAK output.
    let mut cumulative = 0usize;
    let mut output = Vec::with_capacity(plaintext.len());
    for glyph in plaintext {
        let letter = usize::from(glyph.0);
        let shift = shifts.get(letter).copied().unwrap();
        cumulative = (cumulative + shift) % n;
        output.push(((n - cumulative) % n) as u16);
    }
    output
}

/// Draws `count` random permutations of `0..n` whose inverse-image readouts
/// (the position holding card 0, `p^{-1}[0]`) are all distinct, so the
/// deck-realization coset-injectivity rule holds. Requires `count <= n`.
fn random_distinct_coset_letters(n: usize, count: usize, seed: u64) -> Vec<Vec<usize>> {
    let mut rng = SplitMix64::new(seed);
    let mut letters: Vec<Vec<usize>> = Vec::with_capacity(count);
    let mut used_position = vec![false; n];
    let mut produced = 0usize;
    while produced < count {
        let mut perm = (0..n).collect::<Vec<_>>();
        let mut unswapped = perm.len();
        while unswapped > 1 {
            let last = unswapped - 1;
            let partner = random_index_below(unswapped, &mut rng);
            perm.swap(last, partner);
            unswapped = last;
        }
        let zero_position = perm.iter().position(|&entry| entry == 0).unwrap();
        let slot: &mut bool = used_position.as_mut_slice().get_mut(zero_position).unwrap();
        if !*slot {
            *slot = true;
            letters.push(perm);
            produced += 1;
        }
    }
    letters
}

fn values_usize(glyphs: &[Glyph]) -> Vec<usize> {
    glyphs.iter().map(|glyph| usize::from(glyph.0)).collect()
}

fn wrong_left_update_encrypt(plaintext: &[Glyph], key: &AglGakKey) -> Vec<u16> {
    let mut state = key.initial_state();
    let mut output = Vec::new();
    for glyph in plaintext {
        let element = *key.letter_elements().get(usize::from(glyph.0)).unwrap();
        state = agl_compose(element, state, key.alphabet_size());
        output.push(agl_apply(state, key.reference_point(), key.alphabet_size()) as u16);
    }
    output
}

fn random_plaintext(seed: u64, len: usize, alphabet_size: usize) -> Vec<Glyph> {
    let mut rng = SplitMix64::new(seed);
    let mut plaintext = Vec::with_capacity(len);
    let bound = alphabet_size as u64;
    for _position in 0..len {
        let value = rng.next_u64() % bound;
        plaintext.push(Glyph(value as u16));
    }
    plaintext
}

fn shuffled_permutation(alphabet_size: usize, seed: u64) -> Vec<usize> {
    let mut values = (0..alphabet_size).collect::<Vec<_>>();
    let mut rng = SplitMix64::new(seed);
    let mut unswapped = values.len();
    while unswapped > 1 {
        let last = unswapped - 1;
        let partner = random_index_below(unswapped, &mut rng);
        values.swap(last, partner);
        unswapped = last;
    }
    values
}

fn random_index_below(bound: usize, rng: &mut SplitMix64) -> usize {
    let bound = bound as u64;
    loop {
        let draw = rng.next_u64();
        let threshold = u64::MAX - (u64::MAX % bound);
        if draw < threshold {
            return (draw % bound) as usize;
        }
    }
}

fn glyphs(values: &[u16]) -> Vec<Glyph> {
    values.iter().copied().map(Glyph).collect()
}

fn glyphs_from_usize(values: &[usize]) -> Vec<Glyph> {
    values
        .iter()
        .copied()
        .map(|value| Glyph(value as u16))
        .collect()
}

fn values(glyphs: &[Glyph]) -> Vec<u16> {
    glyphs.iter().map(|glyph| glyph.0).collect()
}

fn alphabet(letters: &str) -> Vec<usize> {
    letters
        .bytes()
        .map(|byte| usize::from(byte - b'A'))
        .collect()
}

fn letters(glyphs: &[Glyph]) -> String {
    glyphs
        .iter()
        .map(|glyph| char::from(b'A' + glyph.0 as u8))
        .collect()
}
