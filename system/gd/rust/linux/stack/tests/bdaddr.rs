#[cfg(test)]
mod tests {
    use btstack::BDAddr;

    #[test]
    fn from_string_invalid() {
        assert!(BDAddr::from_string("").is_none());
        assert!(BDAddr::from_string("some invalid string").is_none());
        assert!(BDAddr::from_string("aa:bb:cc:dd:ee:ff:00").is_none());
        assert!(BDAddr::from_string("aa:bb:cc:dd:ee").is_none());
        assert!(BDAddr::from_string("aa:bb:cc:dd::ff").is_none());
    }

    #[test]
    fn from_string_valid() {
        let addr = BDAddr::from_string("11:22:33:aa:bb:cc");
        assert!(addr.is_some());
        assert_eq!([0x11, 0x22, 0x33, 0xaa, 0xbb, 0xcc], addr.unwrap().to_byte_arr());

        // Upper/lower case should not matter.
        let addr = BDAddr::from_string("11:22:33:AA:BB:CC");
        assert!(addr.is_some());
        assert_eq!([0x11, 0x22, 0x33, 0xaa, 0xbb, 0xcc], addr.unwrap().to_byte_arr());
    }

    #[test]
    fn from_byte_vec_invalid() {
        assert!(BDAddr::from_byte_vec(&vec![]).is_none());
        assert!(BDAddr::from_byte_vec(&vec![1, 2, 3, 4, 5]).is_none());
        assert!(BDAddr::from_byte_vec(&vec![1, 2, 3, 4, 5, 6, 7]).is_none());
    }

    #[test]
    fn from_byte_vec_valid() {
        let addr = BDAddr::from_byte_vec(&vec![1, 2, 3, 4, 5, 6]);
        assert!(addr.is_some());
        assert_eq!([1, 2, 3, 4, 5, 6], addr.unwrap().to_byte_arr());
    }
}
