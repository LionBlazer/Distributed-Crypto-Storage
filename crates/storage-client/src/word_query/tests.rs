//! Public nonsecret compiler examples. These metadata fixtures grant no proof status.
use super::*;

fn domain() -> word::StatementDomain {
    word::StatementDomain {
        scope: [Val::from_u32(9); 16],
        enrollment: [Val::from_u32(7); 4],
    }
}
fn material() -> Material {
    let mut old = [Val::ZERO; 208];
    old[33..37].copy_from_slice(&domain().enrollment);
    old[84] = Val::ONE;
    old[85] = Val::ONE;
    old[87] = Val::ONE;
    old[88..96].fill(Val::from_u32(5));
    old[99..107].fill(Val::from_u32(6));
    Material {
        source: word::SourceOpening::checked(Zeroizing::new(vec![0; 2348]), Zeroizing::new([2; 4]))
            .unwrap(),
        registry: word::RegistryOpening::new(
            [[Val::from_u32(5); 8], [Val::from_u32(4); 8]],
            [old, old],
        ),
        actor: Actor {
            slot: 0,
            principal: 1,
            transaction: 1,
        },
        walk: word::WalkInput {
            client: [Val::from_u32(1); 8],
            call: 1,
            invocation: [Val::from_u32(2); 8],
            ..Default::default()
        },
        salts: Zeroizing::new([[3; 4], [4; 4], [5; 4]]),
    }
}
#[test]
fn exact_sql_policy_and_all_truth_bits_reach_the_original_statement() {
    for (strength, mode) in [
        ("KEY SHARE", 1),
        ("SHARE", 2),
        ("NO KEY UPDATE", 3),
        ("UPDATE", 4),
    ] {
        for (option, wait) in [("", 0), ("NOWAIT", 1), ("SKIP LOCKED", 2)] {
            let sql = format!(
                "SELECT age,amount FROM records WHERE age>=128 AND age<255 OFFSET 1 LIMIT 2 FOR {strength} {option}"
            );
            let query = CompiledLockingSelect::compile(&sql)
                .unwrap()
                .prepare(domain(), material())
                .unwrap();
            assert_eq!(
                &query.words[78..86],
                &[
                    0,
                    0,
                    0,
                    0,
                    u32::MAX as u64,
                    u32::MAX as u64,
                    u32::MAX as u64,
                    0x7fffffff
                ]
            );
            assert_eq!(&query.words[86..91], &[mode, wait, 1, 2, 3]);
            assert_eq!(
                &query.words[62..70],
                &query.blinded_sql().map(|v| v.as_canonical_u64())
            );
            assert_ne!(&query.words[91..95], &[0; 4]);
            assert_eq!(query.words[95], 0);
        }
    }
    for (predicate, expected) in [
        ("age=1 OR NULL", [2, 0, 0, 0, 0, 0, 0, 0]),
        ("age NOT IN(1,NULL)", [0; 8]),
        ("age IS NOT NULL", [u32::MAX as u64; 8]),
    ] {
        let sql = format!(
            "SELECT amount FROM records WHERE {predicate} LIMIT NULL OFFSET NULL FOR UPDATE"
        );
        let query = CompiledLockingSelect::compile(&sql)
            .unwrap()
            .prepare(domain(), material())
            .unwrap();
        assert_eq!(&query.words[78..86], &expected);
        assert_eq!(&query.words[86..91], &[4, 0, 0, 4, 2]);
    }
}
#[test]
fn unsupported_sql_or_state_is_rejected_without_a_narrower_substitution() {
    for sql in [
        "SELECT age FROM records",
        "SELECT amount,age FROM records FOR UPDATE",
        "SELECT COUNT(*) FROM records FOR UPDATE",
        "SELECT * FROM records WHERE amount>1 FOR UPDATE",
        "SELECT * FROM records LIMIT 5 FOR UPDATE",
        "SELECT * FROM records OFFSET 5 FOR UPDATE",
        "UPDATE records SET amount=1",
    ] {
        assert!(
            matches!(CompiledLockingSelect::compile(sql), Err(Error::Shape)),
            "{sql}"
        );
    }
    for which in 0..6 {
        let mut m = material();
        match which {
            0 => m.actor.slot = 2,
            1 => m.actor.transaction = 2,
            2 => m.walk.micro = 1,
            3 => m.salts[0][0] = Val::ORDER_U64,
            4 => m.walk.sql[0] = Val::ONE,
            _ => m.walk.statement_salt[0] = Val::ONE,
        }
        assert!(
            CompiledLockingSelect::compile("SELECT age FROM records FOR UPDATE")
                .unwrap()
                .prepare(domain(), m)
                .is_err()
        );
    }
    let mut d = domain();
    d.scope[0] = Val::from_u64(u64::from(u32::MAX) + 1);
    assert!(
        CompiledLockingSelect::compile("SELECT age FROM records FOR UPDATE")
            .unwrap()
            .prepare(d, material())
            .is_err()
    );
}
#[test]
fn fresh_secret_blinding_changes_commitments_and_failed_entropy_creates_no_input() {
    let sql = "SELECT age FROM records WHERE age=42 FOR UPDATE SKIP LOCKED";
    let a = CompiledLockingSelect::compile(sql)
        .unwrap()
        .prepare(domain(), material())
        .unwrap();
    let b = CompiledLockingSelect::compile(sql)
        .unwrap()
        .prepare(domain(), material())
        .unwrap();
    assert_ne!(a.blinded_sql(), b.blinded_sql());
    assert_ne!(a.statement_root(), b.statement_root());
    assert_eq!(&a.words[78..91], &b.words[78..91]);
    assert!(matches!(
        CompiledLockingSelect::compile_with_entropy(sql, &mut |_| Err(Error::Entropy)),
        Err(Error::Entropy)
    ));
    assert!(matches!(
        CompiledLockingSelect::compile_with_entropy(sql, &mut |bytes| {
            bytes.fill(0);
            Ok(())
        }),
        Err(Error::Entropy)
    ));
    let mut calls = 0;
    assert!(matches!(
        CompiledLockingSelect::compile_with_entropy(sql, &mut |bytes| {
            calls += 1;
            bytes.fill(255);
            Ok(())
        }),
        Err(Error::Entropy)
    ));
    assert_eq!(calls, 9);
}
