//! Physical custody and reply construction are distinct availability outcomes.
use super::{test_support::Directory, *};
use crate::{PageAddress, PageBatchRequest, PageImage, ReadImageRequest};

fn fixture() -> (compact_store::Owner, RawBundle) {
    // Public, non-secret generated fixtures; these test custody, not SQL answers.
    let owner = compact_store::Owner::generate([61; 16]).unwrap();
    let image = |schema| {
        owner
            .seal(
                compact_store::Layout {
                    schema: [schema; 16],
                    row_width: 1,
                    rows_per_page: 3,
                    row_count: 7,
                },
                &[schema; 7],
                Limits::default(),
            )
            .unwrap()
    };
    let raw = RawBundle::from_snapshots(&image(62), &image(63)).unwrap();
    (owner, raw)
}
fn page_request(raw: &RawBundle, wrong_heads: bool) -> PageBatchRequest {
    let version = raw.target_version().unwrap();
    let (data, index) = if wrong_heads {
        (version.index_head(), version.data_head())
    } else {
        (version.data_head(), version.index_head())
    };
    PageBatchRequest::new(
        *version.object(),
        data,
        index,
        &[
            PageAddress {
                image: PageImage::Index,
                index: 0,
            },
            PageAddress {
                image: PageImage::Data,
                index: 2,
            },
        ],
    )
    .unwrap()
}
fn read_request(raw: &RawBundle, wrong_heads: bool) -> ReadImageRequest {
    let version = raw.target_version().unwrap();
    let (data, index) = if wrong_heads {
        (version.index_head(), version.data_head())
    } else {
        (version.data_head(), version.index_head())
    };
    ReadImageRequest::new(*version.object(), data, index, 1).unwrap()
}
fn read(
    store: &mut Store,
    raw: &RawBundle,
    image: bool,
    wrong_heads: bool,
) -> Result<(), RemoteError> {
    if image {
        store
            .get_read_image(read_request(raw, wrong_heads))
            .map(|_| ())
    } else {
        store.get_pages(page_request(raw, wrong_heads)).map(|_| ())
    }
}

#[test]
fn successful_physical_repair_clears_invalid_even_when_reply_heads_do_not_match() {
    let directory = Directory::new();
    let mut store = Store::open(&directory.0, 1024 * 1024).unwrap();
    let (_, raw) = fixture();
    let id = *raw.target_version().unwrap().object();
    store.put(raw.clone()).unwrap();
    let path = directory.0.join(filename(&id));
    let original = fs::read(&path).unwrap();
    for image in [false, true] {
        assert!(matches!(
            read(&mut store, &raw, image, true),
            Err(RemoteError::Integrity)
        ));
        assert!(store.objects()[0].available);
        let mut corrupted = original.clone();
        *corrupted.last_mut().unwrap() ^= 1;
        fs::write(&path, corrupted).unwrap();
        assert!(matches!(
            read(&mut store, &raw, image, true),
            Err(RemoteError::Integrity)
        ));
        assert!(!store.objects()[0].available);

        fs::write(&path, &original).unwrap();
        assert!(matches!(
            read(&mut store, &raw, image, true),
            Err(RemoteError::Integrity)
        ));

        assert!(store.objects()[0].available);
        assert!(!store.invalid.contains(&id));
        read(&mut store, &raw, image, false).unwrap();
    }
}

#[test]
fn constructed_custody_replies_outlive_the_disk_buffer_store_and_file() {
    let directory = Directory::new();
    let mut store = Store::open(&directory.0, 1024 * 1024).unwrap();
    let (owner, raw) = fixture();
    store.put(raw.clone()).unwrap();
    let pages_request = page_request(&raw, false);
    let image_request = read_request(&raw, false);

    let pages = store.get_pages(pages_request.clone()).unwrap();
    let image = store.get_read_image(image_request.clone()).unwrap();

    drop(store);
    fs::remove_file(directory.0.join(filename(pages_request.object()))).unwrap();
    let pages = pages.verify(&pages_request).unwrap();
    assert_eq!(
        pages
            .iter()
            .map(|(address, _)| *address)
            .collect::<Vec<_>>(),
        pages_request.addresses()
    );
    assert_eq!(owner.decrypt(&pages[0].1).unwrap().as_bytes(), &[63; 3]);
    assert_eq!(owner.decrypt(&pages[1].1).unwrap().as_bytes(), &[62]);
    image.verify(&image_request).unwrap();
    assert_eq!(image.data().encode(), raw.data);
    assert_eq!(
        owner
            .decrypt(&image.index_page(0, custody_limits()).unwrap())
            .unwrap()
            .as_bytes(),
        &[63; 3]
    );
}

#[test]
fn borrowed_custody_replies_reject_substituted_nonce_and_missing_known_files() {
    let directory = Directory::new();
    let mut store = Store::open(&directory.0, 1024 * 1024).unwrap();
    let (_, raw) = fixture();
    let id = *raw.target_version().unwrap().object();
    store.put(raw.clone()).unwrap();
    let path = directory.0.join(filename(&id));
    let original = fs::read(&path).unwrap();
    let mut other = raw.clone();
    other.nonce[0] ^= 1;
    let substituted = objects::encode_disk(&other).unwrap();
    for image in [false, true] {
        fs::write(&path, &substituted).unwrap();
        assert!(matches!(
            read(&mut store, &raw, image, false),
            Err(RemoteError::Integrity)
        ));
        assert!(!store.objects()[0].available);
        fs::remove_file(&path).unwrap();
        assert!(matches!(
            read(&mut store, &raw, image, false),
            Err(RemoteError::Io(_))
        ));
        fs::write(&path, &original).unwrap();
        read(&mut store, &raw, image, false).unwrap();
        assert!(store.objects()[0].available);
    }
    let mut unknown = raw;
    unknown.nonce[1] ^= 1;
    for image in [false, true] {
        assert!(matches!(
            read(&mut store, &unknown, image, false),
            Err(RemoteError::NotFound)
        ));
    }
    assert_eq!(store.objects().len(), 1);
    assert!(store.objects()[0].available);
}
