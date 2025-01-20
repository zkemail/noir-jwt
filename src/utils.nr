// Taken from https://github.com/madztheo/noir-string-utils/blob/main/src/lib.nr#L33C1-L77C2
// Updated to use the new Noir version

pub fn find_substring_index<N, M>(s: u<N>, substr: str<M>) -> u32 {
    assert(M <= N, "Substring length must be less than or equal to string length");
    let substr_bytes = substr.as_bytes();
    let str_bytes = s.as_bytes();
    let mut index = -1 as u32;
    // To keep track of how many characters of the substring
    // have been found
    let mut match_count = 0;
    for i in 0..N {
        // If the current character matches the first character of the substring
        // and the index is not set, then set the index to the current index
        if (index == -1) & (str_bytes[i] == substr_bytes[0]) {
            index = i as u32;
            match_count += 1;
        } else if (index != -1) & (i - index < M) {
            if (str_bytes[i] != substr_bytes[i - index]) {
                // If any of the subsequent characters don't match, reset the index
                // as this means it's not the right substring
                if (str_bytes[i] == substr_bytes[0]) {
                    // If the current character matches the first character
                    // of the substring, then set the index to the current
                    index = i as u32;
                    match_count = 1;
                } else {
                    // Otherwise, reset the index
                    index = -1;
                    match_count = 0;
                }
            } else {
                // Here the characters match, so we increment the match count
                match_count += 1;
            }
        }
    }

    // If the match count is not equal to the length of the substring,
    // then the substring is not in the string
    // Can happen when looking at a substring that is at the end of the string
    // but the match is only partial
    if match_count != M {
        index = -1;
    }

    index
}
