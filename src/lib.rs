pub mod cert;
pub mod content;
pub mod file;
pub mod include;
pub mod meta;
pub mod user_contents;
mod util;
mod zeruformatter;

pub use json_filter_sorted::*;

pub use cert::Cert;
pub use content::Content;
pub use file::File;
pub use include::Include;
pub use user_contents::UserContents;
pub use util::Number;

#[cfg(test)]
#[cfg_attr(tarpaulin, ignore)]
mod tests {
    use serde_bytes::ByteBuf;

    use crate::user_contents::PermissionRulesType;

    use super::*;

    #[test]
    fn test_verification() {
        let content = Content::from_buf(ByteBuf::from(CONTENT.1.as_bytes())).unwrap();
        let key = CONTENT.0.into();
        let result = content.verify(key);
        assert!(result);
    }

    #[test]
    fn test_unicode_verification() {
        let content = Content::from_buf(ByteBuf::from(CONTENT_UNICODE.1.as_bytes())).unwrap();
        let key = CONTENT_UNICODE.0.into();
        let result = content.verify(key);
        assert!(result);
    }

    #[test]
    fn test_unicode_un_escaped_verification() {
        let content =
            Content::from_buf(ByteBuf::from(CONTENT_UNICODE_UNESCAPED.1.as_bytes())).unwrap();
        let key = CONTENT_UNICODE_UNESCAPED.0.into();
        let result = content.verify(key);
        assert!(result)
    }

    #[test]
    fn test_verification_1() {
        let content = Content::from_buf(ByteBuf::from(CONTENT_TEST.1.as_bytes())).unwrap();
        let key = CONTENT_TEST.0.into();
        let result = content.verify(key);
        assert!(result);
    }

    #[test]
    fn test_verification_2() {
        let content = Content::from_buf(ByteBuf::from(CONTENT_DATA_TEST.1.as_bytes())).unwrap();
        let key = CONTENT_DATA_TEST.0.into();
        let result = content.verify(key);
        assert!(result);
        let user_contents = content.user_contents.unwrap();
        assert_eq!(
            user_contents.cert_signers["zeroid.bit"],
            ["1iD5ZQJMNXu43w1qLB8sfdHVKppVMduGz".to_string()]
        );
        let permission_rules = &user_contents.permission_rules[".*"];
        if let PermissionRulesType::Rules(rules) = permission_rules.clone() {
            assert_eq!(rules.files_allowed, "data.json");
            assert_eq!(rules.files_allowed_optional, ".*\\.(png|jpg|gif)");
            assert_eq!(rules.max_size, 10000);
            assert_eq!(rules.max_size_optional, 10000000);
            assert_eq!(
                rules.signers,
                ["14wgQ4VDDZNoRMFF4yCDuTrBSHmYhL3bet".to_string()]
            );
        } else {
            unreachable!();
        }
        let permission_rules = &user_contents.permission_rules["bitid/.*@zeroid.bit"];
        if let PermissionRulesType::Rules(rules) = permission_rules.clone() {
            assert_eq!(rules.max_size, 40000);
        } else {
            unreachable!();
        }
        let permission_rules = &user_contents.permission_rules["bitmsg/.*@zeroid.bit"];
        if let PermissionRulesType::Rules(rules) = permission_rules.clone() {
            assert_eq!(rules.max_size, 15000);
        } else {
            unreachable!();
        }
        let permission_rules = &user_contents.permissions["bad@zeroid.bit"];
        if let PermissionRulesType::None(value) = permission_rules.clone() {
            assert!(!value);
        }
        let permission_rules = &user_contents.permissions["nofish@zeroid.bit"];
        if let PermissionRulesType::Rules(rules) = permission_rules.clone() {
            assert_eq!(rules.max_size, 100000);
        } else {
            unreachable!();
        }
    }

    #[test]
    fn test_verification_3() {
        let content = Content::from_buf(ByteBuf::from(CONTENT_DATA_TEST_2.1.as_bytes())).unwrap();
        let key = CONTENT_DATA_TEST_2.0.into();
        let result = content.verify(key);
        assert!(result);
        let user_contents = content.user_contents.unwrap();
        assert_eq!(
            user_contents.cert_signers["zeroid.bit"],
            ["1iD5ZQJMNXu43w1qLB8sfdHVKppVMduGz".to_string()]
        );
        let permission_rules = &user_contents.permission_rules[".*"];
        if let PermissionRulesType::Rules(rules) = permission_rules.clone() {
            assert_eq!(rules.files_allowed, "data.json");
            assert_eq!(rules.max_size, 20000);
        } else {
            unreachable!();
        }
        let permission_rules = &user_contents.permission_rules["bitid/.*@zeroid.bit"];
        if let PermissionRulesType::Rules(rules) = permission_rules.clone() {
            assert_eq!(rules.max_size, 40000);
        } else {
            unreachable!();
        }
        let permission_rules = &user_contents.permission_rules["bitmsg/.*@zeroid.bit"];
        if let PermissionRulesType::Rules(rules) = permission_rules.clone() {
            assert_eq!(rules.max_size, 15000);
        } else {
            unreachable!();
        }
        let permission_rules = &user_contents.permissions["bad@zeroid.bit"];
        if let PermissionRulesType::None(value) = permission_rules.clone() {
            assert!(!value);
        }
        let permission_rules = &user_contents.permissions["nofish@zeroid.bit"];
        if let PermissionRulesType::Rules(rules) = permission_rules.clone() {
            assert_eq!(rules.max_size, 100000);
        } else {
            unreachable!();
        }
    }

    #[test]
    fn test_verification_4() {
        let content =
            Content::from_buf(ByteBuf::from(CONTENT_USER_DATA_TEST.1.as_bytes())).unwrap();
        let key = CONTENT_USER_DATA_TEST.0.into();
        let result = content.verify(key);
        assert!(result);

        let cert = content.cert.unwrap();
        let address = content.meta.inner_path.split('/').rev().nth(1).unwrap();
        let valid = cert.verify(address, "1iD5ZQJMNXu43w1qLB8sfdHVKppVMduGz");
        assert!(valid);
        let content =
            Content::from_buf(ByteBuf::from(CONTENT_USER_DATA_TEST_1.1.as_bytes())).unwrap();
        let key = CONTENT_USER_DATA_TEST_1.0.into();
        let result = content.verify(key);
        assert!(result);

        let cert = content.cert.unwrap();
        let address = content.meta.inner_path.split('/').rev().nth(1).unwrap();
        let valid = cert.verify(address, "1iD5ZQJMNXu43w1qLB8sfdHVKppVMduGz");
        assert!(valid);
    }

    #[test]
    fn test_verification_5() {
        let content =
            Content::from_buf(ByteBuf::from(CONTENT_USER_DATA_TEST_2.1.as_bytes())).unwrap();
        let key = CONTENT_USER_DATA_TEST_2.0.into();
        let result = content.verify(key);
        assert!(result);

        let cert = content.cert.unwrap();
        let address = content.meta.inner_path.split('/').rev().nth(1).unwrap();
        let valid = cert.verify(address, "1iD5ZQJMNXu43w1qLB8sfdHVKppVMduGz");
        assert!(valid);

        let content =
            Content::from_buf(ByteBuf::from(CONTENT_USER_DATA_TEST_3.1.as_bytes())).unwrap();
        let key = CONTENT_USER_DATA_TEST_3.0.into();
        let result = content.verify(key);
        assert!(result);

        let cert = content.cert.unwrap();
        let address = content.meta.inner_path.split('/').rev().nth(1).unwrap();
        let valid = cert.verify(address, "1iD5ZQJMNXu43w1qLB8sfdHVKppVMduGz");
        assert!(valid);
    }

    const CONTENT: (&str, &str) = (
        "1JUDmCT4UCSdnPsJAHBoXNkDS61Y31Ue52",
        r#"
			{
			"address": "1JUDmCT4UCSdnPsJAHBoXNkDS61Y31Ue52",
			"address_index": 36579623,
			"background-color": "white",
			"cloneable": true,
			"cloned_from": "1RedkCkVaXuVXrqCMpoXQS29bwaqsuFdL",
			"description": "Home of the bots",
			"files": {
			"data-default/users/content.json-default": {
			"sha512": "4e37699bd5336b9c33ce86a3eb73b82e87460535793401874a653afeddefee59",
			"size": 735
			},
			"index.html": {
			"sha512": "087c6ae46aacc5661f7da99ce10dacc0428dbd48aa7bbdc1df9c2da6e81b1d93",
			"size": 466
			}
			},
			"ignore": "((js|css)/(?!all.(js|css))|data/.*db|data/users/.*/.*)",
			"includes": {
				"data/users/content.json": {
				"signers": [],
				"signers_required": 1
				}
			},
			"inner_path": "content.json",
			"merged_type": "ZeroMe",
			"modified": 1471656205.079839,
			"postmessage_nonce_security": true,
			"sign": [
				60601328857260736769667767617236149396007806053808183569130735997086722937268,
				43661716327244911082383801335054839207111588960552431293232589470692186442781
			],
			"signers_sign": "HEMH4/a7LXic4PYgMj/4toV5jI5z+SX6Bnmo3mP0HoyIGy6e7rUbilJYAH3MrgCT/IXzIn7cnIlhL8VARh7CeUg=",
			"signs": {
				"1JUDmCT4UCSdnPsJAHBoXNkDS61Y31Ue52": "G5qMkd9+n0FMLm2KA4FAN3cz/vaGY/oSYd2k/edx4C+TIv76NQI37NsjXVWtkckMoxvp6rhW8PHZy9Q1MNtmIAM="
			},
			"signs_required": 1,
			"title": "Bot Hub",
			"zeronet_version": "0.4.0"
			}"#,
    );

    const CONTENT_UNICODE: (&str, &str) = (
        "16MQxEQe1U32zDGTKWs1rnc1mU3iL42EB3",
        r#"{
		"address": "16MQxEQe1U32zDGTKWs1rnc1mU3iL42EB3",
		"description": "",
		"files": {},
		"inner_path": "content.json",
		"modified": 1659645497,
		"signers_sign": "Gy9gpZYdEChTxIAxCYfljl8xBBJP0iOYe8Arfs5eMyEdXbSSKmymPGJV1VegBkLt2Br9ltpwWmEarvGXR6Gi638=",
		"signs": {"16MQxEQe1U32zDGTKWs1rnc1mU3iL42EB3": "HNG1x0Bdx2wtC0HDhjIZ7VKEQ6OGhnLGBMXrlCzSAvgKGoPGSQRroPjP+SNtjdWptQ1xHi/efEFFWJx/2aRnZm0="},
		"signs_required": 1,
		"title": "My New Site \\ud83d\\ude01",
		"zeronet_version": "0.8.0"
		}"#,
    );

    const CONTENT_UNICODE_UNESCAPED: (&str, &str) = (
        "16MQxEQe1U32zDGTKWs1rnc1mU3iL42EB3",
        r#"{
		"address": "16MQxEQe1U32zDGTKWs1rnc1mU3iL42EB3",
		"description": "",
		"files": {},
		"inner_path": "content.json",
		"modified": 1659645953,
		"signers_sign": "Gy9gpZYdEChTxIAxCYfljl8xBBJP0iOYe8Arfs5eMyEdXbSSKmymPGJV1VegBkLt2Br9ltpwWmEarvGXR6Gi638=",
		"signs": {"16MQxEQe1U32zDGTKWs1rnc1mU3iL42EB3": "HNF0cx1cGJhyuv9SiIv/PD+drXfX5mvf/cray09ZtDiNenTFfU0SmuAslzhcvn78gY+7y8d+K5S83prn35jiilg="},
		"signs_required": 1,
		"title": "My New Site \ud83d\ude01",
		"zeronet_version": "0.8.0"
		}"#,
    );

    const CONTENT_TEST: (&str, &str) = (
        "1TeSTvb4w2PWE81S2rEELgmX2GCCExQGT",
        r#"{
		"address": "1TeSTvb4w2PWE81S2rEELgmX2GCCExQGT",
		"background-color": "white",
		"description": "Blogging platform Demo",
		"domain": "Blog.ZeroNetwork.bit",
		"files": {
		"css/all.css": {
		"sha512": "65ddd3a2071a0f48c34783aa3b1bde4424bdea344630af05a237557a62bd55dc",
		"size": 112710
		},
		"data-default/data.json": {
		"sha512": "3f5c5a220bde41b464ab116cce0bd670dd0b4ff5fe4a73d1dffc4719140038f2",
		"size": 196
		},
		"data-default/users/content-default.json": {
		"sha512": "0603ce08f7abb92b3840ad0cf40e95ea0b3ed3511b31524d4d70e88adba83daa",
		"size": 679
		},
		"data/data.json": {
		"sha512": "0f2321c905b761a05c360a389e1de149d952b16097c4ccf8310158356e85fb52",
		"size": 31126
		},
		"data/img/autoupdate.png": {
		"sha512": "d2b4dc8e0da2861ea051c0c13490a4eccf8933d77383a5b43de447c49d816e71",
		"size": 24460
		},
		"data/img/direct_domains.png": {
		"sha512": "5f14b30c1852735ab329b22496b1e2ea751cb04704789443ad73a70587c59719",
		"size": 16185
		},
		"data/img/domain.png": {
		"sha512": "ce87e0831f4d1e95a95d7120ca4d33f8273c6fce9f5bbedf7209396ea0b57b6a",
		"size": 11881
		},
		"data/img/memory.png": {
		"sha512": "dd56515085b4a79b5809716f76f267ec3a204be3ee0d215591a77bf0f390fa4e",
		"size": 12775
		},
		"data/img/multiuser.png": {
		"sha512": "88e3f795f9b86583640867897de6efc14e1aa42f93e848ed1645213e6cc210c6",
		"size": 29480
		},
		"data/img/progressbar.png": {
		"sha512": "23d592ae386ce14158cec34d32a3556771725e331c14d5a4905c59e0fe980ebf",
		"size": 13294
		},
		"data/img/slides.png": {
		"sha512": "1933db3b90ab93465befa1bd0843babe38173975e306286e08151be9992f767e",
		"size": 14439
		},
		"data/img/slots_memory.png": {
		"sha512": "82a250e6da909d7f66341e5b5c443353958f86728cd3f06e988b6441e6847c29",
		"size": 9488
		},
		"data/img/trayicon.png": {
		"sha512": "e7ae65bf280f13fb7175c1293dad7d18f1fcb186ebc9e1e33850cdaccb897b8f",
		"size": 19040
		},
		"dbschema.json": {
		"sha512": "2e9466d8aa1f340c91203b4ddbe9b6669879616a1b8e9571058a74195937598d",
		"size": 1527
		},
		"img/loading.gif": {
		"sha512": "8a42b98962faea74618113166886be488c09dad10ca47fe97005edc5fb40cc00",
		"size": 723
		},
		"index.html": {
		"sha512": "c4039ebfc4cb6f116cac05e803a18644ed70404474a572f0d8473f4572f05df3",
		"size": 4667
		},
		"js/all.js": {
		"sha512": "034c97535f3c9b3fbebf2dcf61a38711dae762acf1a99168ae7ddc7e265f582c",
		"size": 201178
		}
		},
		"files_optional": {
		"data/img/zeroblog-comments.png": {
		"sha512": "efe4e815a260e555303e5c49e550a689d27a8361f64667bd4a91dbcccb83d2b4",
		"size": 24001
		},
		"data/img/zeroid.png": {
		"sha512": "b46d541a9e51ba2ddc8a49955b7debbc3b45fd13467d3c20ef104e9d938d052b",
		"size": 18875
		},
		"data/img/zeroname.png": {
		"sha512": "bab45a1bb2087b64e4f69f756b2ffa5ad39b7fdc48c83609cdde44028a7a155d",
		"size": 36031
		},
		"data/img/zerotalk-mark.png": {
		"sha512": "a335b2fedeb8d291ca68d3091f567c180628e80f41de4331a5feb19601d078af",
		"size": 44862
		},
		"data/img/zerotalk-upvote.png": {
		"sha512": "b1ffd7f948b4f99248dde7efe256c2efdfd997f7e876fb9734f986ef2b561732",
		"size": 41092
		},
		"data/img/zerotalk.png": {
		"sha512": "54d10497a1ffca9a4780092fd1bd158c15f639856d654d2eb33a42f9d8e33cd8",
		"size": 26606
		},
		"data/optional.txt": {
		"sha512": "c6f81db0e9f8206c971c9e5826e3ba823ffbb1a3a900f8047652a8bf78ea98fd",
		"size": 6
		}
		},
		"ignore": "((js|css)/(?!all.(js|css))|data/.*db|data/users/.*/.*|data/test_include/.*)",
		"includes": {
		"data/test_include/content.json": {
		"added": 1424976057,
		"files_allowed": "data.json",
		"includes_allowed": false,
		"max_size": 20000,
		"signers": ["15ik6LeBWnACWfaika1xqGapRZ1zh3JpCo"],
		"signers_required": 1,
		"user_id": 47,
		"user_name": "test"
		},
		"data/users/content.json": {
		"signers": ["1LSxsKfC9S9TVXGGNSM3vPHjyW82jgCX5f"],
		"signers_required": 1
		}
		},
		"inner_path": "content.json",
		"modified": 1503257990,
		"optional": "(data/img/zero.*|data/optional.*)",
		"signers_sign": "HDNmWJHM2diYln4pkdL+qYOvgE7MdwayzeG+xEUZBgp1HtOjBJS+knDEVQsBkjcOPicDG2it1r6R1eQrmogqSP0=",
		"signs": {
		"1TeSTvb4w2PWE81S2rEELgmX2GCCExQGT": "G4Uq365UBliQG66ygip1jNGYqW6Eh9Mm7nLguDFqAgk/Hksq/ruqMf9rXv78mgUfPBvL2+XgDKYvFDtlykPFZxk="
		},
		"signs_required": 1,
		"title": "ZeroBlog",
		"zeronet_version": "0.5.7"
		}"#,
    );

    const CONTENT_DATA_TEST: (&str, &str) = (
        "1TeSTvb4w2PWE81S2rEELgmX2GCCExQGT",
        r#"{
		"address": "1TeSTvb4w2PWE81S2rEELgmX2GCCExQGT",
		"files": {},
		"ignore": ".*",
		"inner_path": "data/users/content.json",
		"modified": 1470340815.228,
		"signs": {
		"1TeSTvb4w2PWE81S2rEELgmX2GCCExQGT": "G25hsrlyTOy8PHKuovKDRC7puoBj/OLIZ3U4OJ01izkhE1BBQ+TOgxX96+HXoZGme2/P4IdEnYjc1rqIZ6O+nFk="
		},
		"user_contents": {
		"cert_signers": {
		"zeroid.bit": [ "1iD5ZQJMNXu43w1qLB8sfdHVKppVMduGz" ]
		},
		"permission_rules": {
		".*": {
			"files_allowed": "data.json",
			"files_allowed_optional": ".*\\.(png|jpg|gif)",
			"max_size": 10000,
			"max_size_optional": 10000000,
			"signers": [ "14wgQ4VDDZNoRMFF4yCDuTrBSHmYhL3bet" ]
		},
		"bitid/.*@zeroid.bit": { "max_size": 40000 },
		"bitmsg/.*@zeroid.bit": { "max_size": 15000 }
		},
		"permissions": {
		"bad@zeroid.bit": false,
		"nofish@zeroid.bit": { "max_size": 100000 }
		}
		}
		}"#,
    );

    const CONTENT_DATA_TEST_2: (&str, &str) = (
        "19bq2C77xk9x9RbA7bvmuDKqxX1MsxHvXZ",
        r#"{
		"address": "19bq2C77xk9x9RbA7bvmuDKqxX1MsxHvXZ",
		"files": {},
		"ignore": ".*",
		"inner_path": "data/users/content.json",
		"modified": 1700336232,
		"signs": {"19bq2C77xk9x9RbA7bvmuDKqxX1MsxHvXZ": "G5WwbKLFLTInWtLjJubWa7NajedJ4AIEqTEEHN+mtaaSYOOibHEDnv/N+tlCmSauXIOKrck3TyhkyZd2Lw+IGmg="},
		"user_contents": {
		"cert_signers": {
		"kxoid.bit": ["12F5SvxoPR128aiudte78h8pY7mobroG6V","18Mt3CWBpiqJBLsPSu5JxB4B9MeaSwhyJ"],
		"zeroid.bit": ["1iD5ZQJMNXu43w1qLB8sfdHVKppVMduGz"]
		},
		"optional": null,
		"permission_rules": {
		".*": {
			"files_allowed": "data.json",
			"max_size": 20000
		},
		"bitid/.*@zeroid.bit": {"max_size": 40000},
		"bitmsg/.*@zeroid.bit": {"max_size": 15000}
		},
		"permissions": {
		"bad@zeroid.bit": false,
		"nofish@zeroid.bit": {"max_size": 100000}
		}
		}
		}"#,
    );

    const CONTENT_USER_DATA_TEST: (&str, &str) = (
        "1AmeB7f5wBfJm6iR7MRZfFh65xkJzaVCX7",
        r#"{
		"address": "15UYrA7aXr2Nto1Gg4yWXpY3EAJwafMTNk",
		"cert_auth_type": "web",
		"cert_sign": "G7suwq3UAUQyJtvznnFEp4NxkYwLaRd/7vOVAcrfWPzrJf0Cw08/3xdGkuTiwXcOIsdAlTPLXvGkfrBf3T/FfKc=",
		"cert_user_id": "pramukesh@zeroid.bit",
		"files": {
		"data.json": {
		"sha512": "f8ba88089df37523f58fc4dd7a3c91022d3ef7af5be0aa7caebb95736b566b00",
		"size": 121339
		}
		},
		"inner_path": "data/users/1AmeB7f5wBfJm6iR7MRZfFh65xkJzaVCX7/content.json",
		"modified": 1699638671,
		"signs": {"1AmeB7f5wBfJm6iR7MRZfFh65xkJzaVCX7": "G6yN4hSiDCkmQa/DSvsN4aeQ//anz3SLadL7OmC7xDeUYfyK+gUeWZk5yhlfAvDX8E3IV/4b32VLgWg8bHXyKpk="}
		}"#,
    );

    const CONTENT_USER_DATA_TEST_1: (&str, &str) = (
        "1AmeB7f5wBfJm6iR7MRZfFh65xkJzaVCX7",
        r#"{
		"address": "1UDbADib99KE9d3qZ87NqJF2QLTHmMkoV",
		"cert_auth_type": "web",
		"cert_sign": "G7suwq3UAUQyJtvznnFEp4NxkYwLaRd/7vOVAcrfWPzrJf0Cw08/3xdGkuTiwXcOIsdAlTPLXvGkfrBf3T/FfKc=",
		"cert_user_id": "pramukesh@zeroid.bit",
		"files": {},
		"inner_path": "data/userdb/1AmeB7f5wBfJm6iR7MRZfFh65xkJzaVCX7/content.json",
		"modified": 1678991701,
		"signs": {"1AmeB7f5wBfJm6iR7MRZfFh65xkJzaVCX7": "HNz5ARtOPvcC7emwOouWA/Rxc1rBYXahFHNShIrxZbUxLjCzSW13u9TduCLu1hg2vElgWLmsBwrNy/6SEnX+KMo="},
		"user": [
		{
		"avatar": "png",
		"date_added": 1638470325,
		"hub": "1MoonP8t4rk9QamBUPh5Aspkwa1Xhf5ux2",
		"intro": "ZeroNetX & ZeroNet Mobile Dev\nhttps://zeronet.dev\n\nZeroId : 1AmeB7f5wBfJm6iR7MRZfFh65xkJzaVCX7\n\nOfficial Site Links : \nClearnet link : https://zeronet.dev\nOfficial Zite on ZeroNetX : [ZeroNetX](/1ZeroNetyV5mKY9JF1gsm82TuBXHpfdLX)\n\nUpdater Link : [Click to update](/1Update8crprmciJHwp2WXqkx2c4iYp18)\nZeroNet Proxy: https://proxy.zeronet.dev","user_name": "PramUkesh"}]
		}"#,
    );

    const CONTENT_USER_DATA_TEST_2: (&str, &str) = (
        "129AZxKKZFQAyrSxv8ocZtZzPU1Gy6Ua71",
        r#"{
		"address": "1MoonP8t4rk9QamBUPh5Aspkwa1Xhf5ux2",
		"cert_auth_type": "web",
		"cert_sign": "G+s0pxaa/UAULg+rHsCaKVam/Ey7TJ1EMJ2MkuxvBOveUPFE4vc5NqCCMceswY21/JK5UTAuhXrEtVriA1GJYp0=",
		"cert_user_id": "zeromepro@zeroid.bit",
		"files": {
		"avatar.jpg": {
		"sha512": "da2ba9a8d12b7eac9090af00bb25cb183b560b4be72dfa49c6efb9c43b5da12d",
		"size": 1097
		},
		"data.json": {
		"sha512": "906887b40495669116a9e3a666e152c88fbffdda7193a1a6f207eca2dbdb3c9c",
		"size": 5850
		}
		},
		"files_optional": {
		"1600766340.jpg": {
		"sha512": "9631c28627d894daeb8a3fd664d64dd372ca64ed58f7bdcff976e99abef1499d",
		"size": 23600
		}
		},
		"inner_path": "data/users/129AZxKKZFQAyrSxv8ocZtZzPU1Gy6Ua71/content.json",
		"modified": 1607847767,
		"optional": "(?!avatar).*jpg",
		"signs": {"129AZxKKZFQAyrSxv8ocZtZzPU1Gy6Ua71": "G15Z/ymSgNasNPkfkp5tjQeOnqrFlDwltkGp22vAIR5VbmH7WhnpHELq9hocPWh6BTl+B4XGe7d3EAIPXAjZDPs="}
		}"#,
    );

    const CONTENT_USER_DATA_TEST_3: (&str, &str) = (
        "129AZxKKZFQAyrSxv8ocZtZzPU1Gy6Ua71",
        r#"{
		"address": "1UDbADib99KE9d3qZ87NqJF2QLTHmMkoV",
		"cert_auth_type": "web",
		"cert_sign": "G+s0pxaa/UAULg+rHsCaKVam/Ey7TJ1EMJ2MkuxvBOveUPFE4vc5NqCCMceswY21/JK5UTAuhXrEtVriA1GJYp0=",
		"cert_user_id": "zeromepro@zeroid.bit",
		"files": {},
		"inner_path": "data/userdb/129AZxKKZFQAyrSxv8ocZtZzPU1Gy6Ua71/content.json",
		"modified": 1601718327,
		"signs": {"129AZxKKZFQAyrSxv8ocZtZzPU1Gy6Ua71": "HFNCXOTvWfh8fzZQGg8HDtwekRb2du4300ubRMuIJOCjQrujpVrObvC93+Udk16J3O0LS5fG8sH7hHgM2UpRXrc="},
		"user": [
		{
		"avatar": "jpg",
		"date_added": 1578698807,
		"hub": "1MoonP8t4rk9QamBUPh5Aspkwa1Xhf5ux2",
		"intro": "Random ZeroNet user ! Am i ?\nDeveloper of ZeroNet Mobile App. \nThinking about Leaving my Career to Develop Modern P2P technologies that must impact future generations, Aiming at big hopes for technological changes. Dare to hold this aim because intentionally left my Chartered Accountant education, which is much different from technology.\n\nGithub : [canewsin](https://github.com/canewsin)\n\n### Life Time Goals :\n- Create a P2P network.\n- Create a Payment System.\n- Create an OS from Scratch.","user_name": "zeromepro"}]
		}"#,
    );
}
