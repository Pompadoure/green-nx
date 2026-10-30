// Installs a home screen forwarder for one xCloud title, on the console and
// without prod.keys: the header key comes from the spl service.
//
// The NCA, romfs and NPDM builders below are taken from sphaira's owo.cpp
// (https://github.com/ITotalJustice/sphaira, GPL-3.0), which is itself based on
// hacbrewpack. vendor/hbl holds the forwarder's loader; see its README.

#include "forwarder.hpp"

#ifdef __SWITCH__
#include <SDL2/SDL.h>
#include <SDL2/SDL_image.h>
#include <switch.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <vector>

#define R_TRY(expr)                    \
    do {                               \
        const Result rc_ = (expr);     \
        if (R_FAILED(rc_)) return rc_; \
    } while (0)

__asm__(
    ".pushsection .rodata\n"
    "gnx_hbl_main:\n .incbin \"hbl/main\"\n"
    "gnx_hbl_main_end:\n"
    "gnx_hbl_npdm:\n .incbin \"hbl/main.npdm\"\n"
    "gnx_hbl_npdm_end:\n"
    ".popsection\n");
extern "C" const u8 gnx_hbl_main[], gnx_hbl_main_end[];
extern "C" const u8 gnx_hbl_npdm[], gnx_hbl_npdm_end[];

namespace gnx::forwarder {
namespace {

namespace nca {
#define NCA0_MAGIC 0x3041434E
#define NCA2_MAGIC 0x3241434E
#define NCA3_MAGIC 0x3341434E

#define NCA_SECTOR_SIZE             0x200
#define NCA_XTS_SECTION_SIZE        0xC00
#define NCA_SECTION_TOTAL           0x4
#define NCA_MEDIA_REAL(x)((u64(x) * 0x200))

#define NCA_PROGRAM_LOGO_OFFSET     0x8000
#define NCA_META_CNMT_OFFSET        0xC20

enum KeyGenerationOld {
    KeyGenerationOld_100    = 0x0,
    KeyGenerationOld_Unused = 0x1,
    KeyGenerationOld_300    = 0x2,
};

enum KeyGeneration {
    KeyGeneration_301     = 0x3,
    KeyGeneration_400     = 0x4,
    KeyGeneration_500     = 0x5,
    KeyGeneration_600     = 0x6,
    KeyGeneration_620     = 0x7,
    KeyGeneration_700     = 0x8,
    KeyGeneration_810     = 0x9,
    KeyGeneration_900     = 0x0A,
    KeyGeneration_910     = 0x0B,
    KeyGeneration_1210    = 0x0C,
    KeyGeneration_1300    = 0x0D,
    KeyGeneration_1400    = 0x0E,
    KeyGeneration_1500    = 0x0F,
    KeyGeneration_1600    = 0x10,
    KeyGeneration_1700    = 0x11,
    KeyGeneration_1800    = 0x12,
    KeyGeneration_1900    = 0x13,
    KeyGeneration_2000    = 0x14,
    KeyGeneration_Invalid = 0xFF,
};

enum KeyAreaEncryptionKeyIndex {
    KeyAreaEncryptionKeyIndex_Application = 0x0,
    KeyAreaEncryptionKeyIndex_Ocean       = 0x1,
    KeyAreaEncryptionKeyIndex_System      = 0x2
};

enum DistributionType {
    DistributionType_System   = 0x0,
    DistributionType_GameCard = 0x1
};

enum ContentType {
    ContentType_Program    = 0x0,
    ContentType_Meta       = 0x1,
    ContentType_Control    = 0x2,
    ContentType_Manual     = 0x3,
    ContentType_Data       = 0x4,
    ContentType_PublicData = 0x5,
};

enum FileSystemType {
    FileSystemType_RomFS = 0x0,
    FileSystemType_PFS0  = 0x1
};

enum HashType {
    HashType_Auto                    = 0x0,
    HashType_HierarchicalSha256      = 0x2,
    HashType_HierarchicalIntegrity   = 0x3
};

enum EncryptionType {
    EncryptionType_Auto                  = 0x0,
    EncryptionType_None                  = 0x1,
    EncryptionType_AesXts                = 0x2,
    EncryptionType_AesCtr                = 0x3,
    EncryptionType_AesCtrEx              = 0x4,
    EncryptionType_AesCtrSkipLayerHash   = 0x5, // [14.0.0+]
    EncryptionType_AesCtrExSkipLayerHash = 0x6, // [14.0.0+]
};

struct SectionTableEntry {
    u32 media_start_offset; // divided by 0x200.
    u32 media_end_offset;   // divided by 0x200.
    u8 _0x8[0x4];           // unknown.
    u8 _0xC[0x4];           // unknown.

    auto IsValid() const -> bool {
        return media_start_offset && media_end_offset;
    }

    auto GetOffset() const -> u64 {
        return NCA_MEDIA_REAL(media_start_offset);
    }

    auto GetOffsetEnd() const -> u64 {
        return NCA_MEDIA_REAL(media_end_offset);
    }

    auto GetSize() const -> u64 {
        return GetOffsetEnd() - GetOffset();
    }
};

struct LayerRegion {
    u64 offset;
    u64 size;
};

struct HierarchicalSha256Data {
    u8 master_hash[0x20];
    u32 block_size;
    u32 layer_count;
    LayerRegion hash_layer;
    LayerRegion pfs0_layer;
    LayerRegion unused_layers[3];
    u8 _0x78[0x80];
};

#pragma pack(push, 1)
struct HierarchicalIntegrityVerificationLevelInformation {
    u64 logical_offset;
    u64 hash_data_size;
    u32 block_size; // log2
    u32 _0x14; // reserved
};
#pragma pack(pop)

struct InfoLevelHash {
    u32 max_layers;
    HierarchicalIntegrityVerificationLevelInformation levels[6];
    u8 signature_salt[0x20];
};

struct IntegrityMetaInfo {
    u32 magic; // IVFC
    u32 version;
    u32 master_hash_size;
    InfoLevelHash info_level_hash;
    u8 master_hash[0x20];
    u8 _0xE0[0x18];
};

static_assert(sizeof(HierarchicalSha256Data) == 0xF8);
static_assert(sizeof(IntegrityMetaInfo) == 0xF8);
static_assert(sizeof(HierarchicalSha256Data) == sizeof(IntegrityMetaInfo));

struct BucketTreeHeader {
    u32 magic; // BKTR
    u32 version;
    u32 count;
    u8 _0xC[0x4];
};

struct PatchInfo {
    u64 indirect_offset;
    u64 indirect_size;
    BucketTreeHeader indirect_header;
    u64 aes_ctr_offset;
    u64 aes_ctr_size;
    BucketTreeHeader aes_ctr_header;
};
static_assert(sizeof(PatchInfo) == 0x40);

struct CompressionInfo {
    u64 table_offset;
    u64 table_size;
    BucketTreeHeader table_header;
    u8 _0x20[0x8];
};
static_assert(sizeof(CompressionInfo) == 0x28);

struct BktrEntry {
    u8 _0x0[0x4];
    u32 count;
    u64 size;
    u64 offsets[0x3FF0 / sizeof(u64)];
};
static_assert(sizeof(BktrEntry) == 0x4000);

struct NX_PACKED BktrRelocationEntry {
    u64 patched_addr;
    u64 source_addr;
    u32 flag;
};
static_assert(sizeof(BktrRelocationEntry) == 0x14);

struct BktrRelocationBucket {
    u8 _0x0[0x4];
    u32 count;
    u64 end_offset;
    BktrRelocationEntry entries[0x3FF0 / sizeof(BktrRelocationEntry)];
    u8 _[0x3FF0 % sizeof(BktrRelocationEntry)];
};
static_assert(sizeof(BktrRelocationBucket) == 0x4000);

struct FsHeader {
    u16 version;           // always 2.
    u8 fs_type;            // see FileSystemType.
    u8 hash_type;          // see HashType.
    u8 encryption_type;    // see EncryptionType.
    u8 metadata_hash_type;
    u8 _0x6[0x2];          // empty.

    union {
        HierarchicalSha256Data hierarchical_sha256_data;
        IntegrityMetaInfo integrity_meta_info; // used for romfs
    } hash_data;

    PatchInfo patch_info;
    u64 section_ctr;
    u8 spares_info[0x30];
    CompressionInfo compression_info;
    u8 meta_data_hash_data_info[0x30];
    u8 reserved[0x30];

    auto IsValid() const -> bool {
        return version == 2;
    }
};
static_assert(sizeof(FsHeader) == 0x200);
static_assert(sizeof(FsHeader::hash_data) == 0xF8);

struct SectionHeaderHash {
    u8 sha256[0x20];
};

struct KeyArea {
    u8 area[0x10];
};

struct Header {
    u8 rsa_fixed_key[0x100];
    u8 rsa_npdm[0x100];        // key from npdm.
    u32 magic;
    u8 distribution_type;      // see DistributionType.
    u8 content_type;           // see ContentType.
    u8 old_key_gen;            // see KeyGenerationOld.
    u8 kaek_index;             // see KeyAreaEncryptionKeyIndex.
    u64 size;
    u64 program_id;
    u32 context_id;
    union {
        u32 sdk_version;
        struct {
            u8 sdk_revision;
            u8 sdk_micro;
            u8 sdk_minor;
            u8 sdk_major;
        };
    };
    u8 key_gen;                // see KeyGeneration.
    u8 sig_key_gen;
    u8 _0x222[0xE];            // empty.
    FsRightsId rights_id;

    SectionTableEntry fs_table[NCA_SECTION_TOTAL];
    SectionHeaderHash fs_header_hash[NCA_SECTION_TOTAL];
    KeyArea key_area[NCA_SECTION_TOTAL];

    u8 _0x340[0xC0];           // empty.

    FsHeader fs_header[NCA_SECTION_TOTAL];

    auto IsValid() const -> bool {
        return magic == NCA3_MAGIC;
    }

    auto GetKeyGeneration() const -> u8 {
        if (old_key_gen < key_gen) {
            return key_gen;
        } else {
            return old_key_gen;
        }
    }

    void SetKeyGeneration(u8 key_generation) {
        if (key_generation <= 0x2) {
            old_key_gen = key_generation;
            key_gen = 0;
        } else {
            old_key_gen = 0x2;
            key_gen = key_generation;
        }
    }

    auto GetSectionCount() const -> u8 {
        u8 count = 0;
        for (u32 i = 0; i < NCA_SECTION_TOTAL; i++) {
            if (!fs_header[i].IsValid() || !fs_table[i].IsValid()) {
                break;
            }
            count++;
        }
        return count;
    }
};
}  // namespace nca

namespace npdm {
struct Meta {
    u32 magic; // "META"
    u32 signature_key_generation; // +9.0.0
    u32 _0x8;
    u8 flags;
    u8 _0xD;
    u8 main_thread_priority;
    u8 main_thread_core_num;
    u32 _0x10;
    u32 sys_resource_size; // +3.0.0
    u32 version;
    u32 main_thread_stack_size;
    char title_name[0x10];
    char product_code[0x10];
    u8 _0x40[0x30];
    u32 aci0_offset;
    u32 aci0_size;
    u32 acid_offset;
    u32 acid_size;
};

struct Acid {
    u8 rsa_sig[0x100];
    u8 rsa_pub[0x100];
    u32 magic; // "ACID"
    u32 size;
    u8 version;
    u8 _0x209[0x1];
    u8 _0x20A[0x2];
    u32 flags;
    u64 program_id_min;
    u64 program_id_max;
    u32 fac_offset;
    u32 fac_size;
    u32 sac_offset;
    u32 sac_size;
    u32 kac_offset;
    u32 kac_size;
    u8 _0x238[0x8];
};

struct Aci0 {
    u32 magic; // "ACI0"
    u8 _0x4[0xC];
    u64 program_id;
    u8 _0x18[0x8];
    u32 fac_offset;
    u32 fac_size;
    u32 sac_offset;
    u32 sac_size;
    u32 kac_offset;
    u32 kac_size;
    u8 _0x38[0x8];
};
}  // namespace npdm

namespace ncm {
struct ContentStorageRecord {
    NcmContentMetaKey key;
    u8 storage_id;  // NcmStorageId
    u8 padding[0x7];
};
}  // namespace ncm

namespace keys {
struct Keys {
    u8 header_key[0x20]{};
};
}  // namespace keys

enum class ForwarderAddressSpace : u8 { Bit36 = 1 };
enum class CpuCoreMode : u8 { Three = 3, Four = 4 };
enum class ForwarderSvcDebugMode : u8 { Automatic, Enabled, Disabled };

template <typename F>
struct ScopeExit {
    F fn;
    ~ScopeExit() { fn(); }
};
template <typename F>
ScopeExit(F) -> ScopeExit<F>;
#define GNX_CONCAT2(a, b) a##b
#define GNX_CONCAT(a, b) GNX_CONCAT2(a, b)
#define ON_SCOPE_EXIT(expr) \
    ScopeExit GNX_CONCAT(scope_exit_, __LINE__){[&]() { expr; }}

// NacpStruct's language table moved in newer libnx; its binary layout did not.
struct LanguageRange {
    NacpLanguageEntry* first;
    NacpLanguageEntry* begin() { return first; }
    NacpLanguageEntry* end() { return first + 16; }
};
LanguageRange NacpLanguageEntries(NacpStruct& nacp) {
    return {reinterpret_cast<NacpLanguageEntry*>(&nacp)};
}

constexpr u32 IVFC_MAX_LEVEL = 6;
constexpr u32 IVFC_HASH_BLOCK_SIZE = 0x4000;
constexpr u32 PFS0_EXEFS_HASH_BLOCK_SIZE = 0x10000;
constexpr u32 PFS0_LOGO_HASH_BLOCK_SIZE = 0x1000;
constexpr u32 PFS0_META_HASH_BLOCK_SIZE = 0x1000;
constexpr u32 PFS0_PADDING_SIZE = 0x200;
constexpr u32 ROMFS_ENTRY_EMPTY = 0xFFFFFFFF;
constexpr u32 ROMFS_FILEPARTITION_OFS = 0x200;


// stdio-like wrapper for std::vector
struct BufHelper {
    void write(const void* data, u64 size) {
        if (offset + size >= buf.size()) {
            buf.resize(offset + size);
        }
        std::memcpy(buf.data() + offset, data, size);
        offset += size;
    }

    void seek(u64 where_to) {
        offset = where_to;
    }

    [[nodiscard]]
    auto tell() const {
        return offset;
    }

    std::vector<u8> buf;
    u64 offset{};
};

struct NcaEntry {
    NcaEntry(const BufHelper& buf, NcmContentType _type) : data{buf.buf}, type{_type} {
        sha256CalculateHash(hash, data.data(), data.size());
    }

    const std::vector<u8> data;
    const u8 type;
    u8 hash[SHA256_HASH_SIZE];
};

struct CnmtHeader {
    u64 title_id;
    u32 title_version;
    u8 meta_type; // NcmContentMetaType
    u8 _0xD;
    NcmContentMetaHeader meta_header;
    u8 install_type; // NcmContentInstallType
    u8 _0x17;
    u32 required_sys_version;
    u8 _0x1C[0x4];
};
static_assert(sizeof(CnmtHeader) == 0x20);

struct NcmContentMetaData {
    NcmContentMetaHeader header;
    NcmApplicationMetaExtendedHeader extended;
    NcmContentInfo infos[3];
};

struct NcaMetaEntry {
    NcaMetaEntry(const BufHelper& buf, NcmContentType type) : nca_entry{buf, type} { }

    NcaEntry nca_entry;
    NcmContentMetaHeader content_meta_header{};
    NcmContentMetaKey content_meta_key{};
    ncm::ContentStorageRecord content_storage_record{};
    NcmContentMetaData content_meta_data{};
};

struct Pfs0Header {
    u32 magic;
    u32 total_files;
    u32 string_table_size;
    u32 padding;
};

struct Pfs0FileTable {
    u64 data_offset;
    u64 data_size;
    u32 name_offset;
    u32 padding;
};

struct Pfs0StringTable {
    char name[256];
};

struct FileEntry {
    std::string name;
    std::vector<u8> data;
};

using FileEntries = std::vector<FileEntry>;

struct NpdmPatch {
    char title_name[0x10]{"Application"};
    char product_code[0x10]{};
    u64 tid;
    ForwarderAddressSpace address_space{ForwarderAddressSpace::Bit36};
    CpuCoreMode core_mode{CpuCoreMode::Three};
    ForwarderSvcDebugMode svc_debug_mode{ForwarderSvcDebugMode::Automatic};
};

struct NcapPatch {
    std::string name;
    std::string author;
    u64 tid;
    bool profile_selection{};
    bool screenshot{true};
    bool video_capture{true};
};

typedef struct romfs_dirent_ctx {
    u32 entry_offset;
    struct romfs_dirent_ctx *parent; /* Parent node */
    struct romfs_dirent_ctx *child; /* Child node */
    struct romfs_dirent_ctx *sibling; /* Sibling node */
    struct romfs_fent_ctx *file; /* File node */
    struct romfs_dirent_ctx *next; /* Next node */
} romfs_dirent_ctx_t;

typedef struct romfs_fent_ctx {
    u32 entry_offset;
    u64 offset;
    u64 size;
    romfs_dirent_ctx_t *parent; /* Parent dir */
    struct romfs_fent_ctx *sibling; /* Sibling file */
    struct romfs_fent_ctx *next; /* Logical next file */
} romfs_fent_ctx_t;

typedef struct {
    romfs_fent_ctx_t *files;
    u64 num_dirs;
    u64 num_files;
    u64 dir_table_size;
    u64 file_table_size;
    u64 dir_hash_table_size;
    u64 file_hash_table_size;
    u64 file_partition_size;
} romfs_ctx_t;

auto write_padding(BufHelper& buf, u64 off, u64 block) -> u64 {
    const u64 size = block - (off % block);
    if (size) {
        std::vector<u8> padding(size);
        buf.write(padding.data(), padding.size());
    }
    return size;
}

auto romfs_get_direntry(romfs_dir *directories, u32 offset) -> romfs_dir* {
    return (romfs_dir*)((u8*)directories + offset);
}

auto romfs_get_fentry(romfs_file *files, u32 offset) -> romfs_file* {
    return (romfs_file*)((u8*)files + offset);
}

auto calc_path_hash(u32 parent, const u8 *path, u32 start, u32 path_len) -> u32 {
    u32 hash = parent ^ 123456789;
    for (u32 i = 0; i < path_len; i++) {
        hash = (hash >> 5) | (hash << 27);
        hash ^= path[start + i];
    }

    return hash;
}

auto align(u32 offset, u32 alignment) -> u32 {
    const u32 mask = ~(alignment - 1);
    return (offset + (alignment - 1)) & mask;
}

auto align64(u64 offset, u64 alignment) -> u64 {
    const u64 mask = ~(u64)(alignment - 1);
    return (offset + (alignment - 1)) & mask;
}

auto romfs_get_hash_table_count(u32 num_entries) -> u32 {
    if (num_entries < 3) {
        return 3;
    } else if (num_entries < 19) {
        return num_entries | 1;
    }

    u32 count = num_entries;
    while (count % 2 == 0 || count % 3 == 0 || count % 5 == 0 || count % 7 == 0 || count % 11 == 0 || count % 13 == 0 || count % 17 == 0) {
        count++;
    }

    return count;
}

void romfs_visit_dir(const FileEntries& entries, romfs_dirent_ctx_t *parent, romfs_ctx_t *romfs_ctx) {
    romfs_dirent_ctx_t *child_dir_tree = NULL;
    romfs_fent_ctx_t *child_file_tree = NULL;
    romfs_fent_ctx_t *cur_file = NULL;

    for (auto& e : entries) {
        /* File */
        cur_file = (romfs_fent_ctx_t*)calloc(1, sizeof(romfs_fent_ctx_t));

        romfs_ctx->num_files++;

        cur_file->parent = parent;
        cur_file->size = e.data.size();

        romfs_ctx->file_table_size += sizeof(romfs_file) + align(e.name.length() - 1, 4);

        /* Ordered insertion on sibling */
        if (child_file_tree == NULL) {
            cur_file->sibling = child_file_tree;
            child_file_tree = cur_file;
        } else {
            romfs_fent_ctx_t *child, *prev;
            prev = child_file_tree;
            child = child_file_tree->sibling;
            prev->sibling = cur_file;
            cur_file->sibling = child;
        }

        /* Ordered insertion on next */
        if (romfs_ctx->files == NULL) {
            cur_file->next = romfs_ctx->files;
            romfs_ctx->files = cur_file;
        } else {
            romfs_fent_ctx_t *child, *prev;
            prev = romfs_ctx->files;
            child = romfs_ctx->files->next;
            prev->next = cur_file;
            cur_file->next = child;
        }

        cur_file = NULL;
    }

    parent->child = child_dir_tree;
    parent->file = child_file_tree;
}

void build_romfs_into_file(const FileEntries& entries, BufHelper& buf) {
    auto root_ctx = (romfs_dirent_ctx_t*)calloc(1, sizeof(romfs_dirent_ctx_t));
    root_ctx->parent = root_ctx;

    romfs_ctx_t romfs_ctx{};

    romfs_ctx.dir_table_size = sizeof(romfs_dir); /* Root directory. */
    romfs_ctx.num_dirs = 1;

    /* Visit all directories. */
    romfs_visit_dir(entries, root_ctx, &romfs_ctx);
    const u32 dir_hash_table_entry_count = romfs_get_hash_table_count(romfs_ctx.num_dirs);
    const u32 file_hash_table_entry_count = romfs_get_hash_table_count(romfs_ctx.num_files);
    romfs_ctx.dir_hash_table_size = 4 * dir_hash_table_entry_count;
    romfs_ctx.file_hash_table_size = 4 * file_hash_table_entry_count;

    romfs_header header{};
    romfs_fent_ctx_t *cur_file{};
    romfs_dirent_ctx_t *cur_dir{};
    u32 entry_offset{};

    std::vector<u32> dir_hash_table(dir_hash_table_entry_count, ROMFS_ENTRY_EMPTY);
    std::vector<u32> file_hash_table(file_hash_table_entry_count, ROMFS_ENTRY_EMPTY);

    auto dir_table = (romfs_dir*)calloc(1, romfs_ctx.dir_table_size);
    auto file_table = (romfs_file *)calloc(1, romfs_ctx.file_table_size);

    /* Determine file offsets. */
    cur_file = romfs_ctx.files;
    entry_offset = 0;
    for (auto& e : entries) {
        romfs_ctx.file_partition_size = align64(romfs_ctx.file_partition_size, 0x10);
        cur_file->offset = romfs_ctx.file_partition_size;
        romfs_ctx.file_partition_size += cur_file->size;
        cur_file->entry_offset = entry_offset;
        entry_offset += sizeof(romfs_file) + align(e.name.length() - 1, 4);
        cur_file = cur_file->next;
    }

    /* Determine dir offsets. */
    root_ctx->entry_offset = 0x0;

    /* Populate file tables. */
    cur_file = romfs_ctx.files;
    for (auto& e : entries) {
        auto cur_entry = romfs_get_fentry(file_table, cur_file->entry_offset);
        cur_entry->parent = (cur_file->parent->entry_offset);
        cur_entry->sibling = (cur_file->sibling == NULL ? ROMFS_ENTRY_EMPTY : cur_file->sibling->entry_offset);
        cur_entry->dataOff = (cur_file->offset);
        cur_entry->dataSize = (cur_file->size);

        const u32 name_size = e.name.length() - 1;
        const u32 hash = calc_path_hash(cur_file->parent->entry_offset, (const u8 *)e.name.c_str(), 1, name_size);
        cur_entry->nextHash = file_hash_table[hash % file_hash_table_entry_count];
        file_hash_table[hash % file_hash_table_entry_count] = (cur_file->entry_offset);

        cur_entry->nameLen = name_size;
        std::memcpy(cur_entry->name, e.name.c_str() + 1, name_size);

        cur_file = cur_file->next;
    }

    /* Populate dir tables. */
    cur_dir = root_ctx;

    while (cur_dir != NULL) {
        auto cur_entry = romfs_get_direntry(dir_table, cur_dir->entry_offset);
        cur_entry->parent = cur_dir->parent->entry_offset;
        cur_entry->sibling = cur_dir->sibling == NULL ? ROMFS_ENTRY_EMPTY : cur_dir->sibling->entry_offset;
        cur_entry->childDir = cur_dir->child == NULL ? ROMFS_ENTRY_EMPTY : cur_dir->child->entry_offset;
        cur_entry->childFile = cur_dir->file == NULL ? ROMFS_ENTRY_EMPTY : cur_dir->file->entry_offset;

        const auto hash = calc_path_hash(0, 0, 0, 0);
        cur_entry->nextHash = dir_hash_table[hash % dir_hash_table_entry_count];
        dir_hash_table[hash % dir_hash_table_entry_count] = (cur_dir->entry_offset);

        cur_entry->nameLen = 0;

        auto temp = cur_dir;
        cur_dir = cur_dir->next;
        free(temp);
    }

    header.headerSize = sizeof(header);
    header.fileHashTableSize = romfs_ctx.file_hash_table_size;
    header.fileTableSize = romfs_ctx.file_table_size;
    header.dirHashTableSize = romfs_ctx.dir_hash_table_size;
    header.dirTableSize = romfs_ctx.dir_table_size;
    header.fileDataOff = ROMFS_FILEPARTITION_OFS;

    header.dirHashTableOff = align64(romfs_ctx.file_partition_size + ROMFS_FILEPARTITION_OFS, 4);
    header.dirTableOff = header.dirHashTableOff + romfs_ctx.dir_hash_table_size;
    header.fileHashTableOff = header.dirTableOff + romfs_ctx.dir_table_size;
    header.fileTableOff = header.fileHashTableOff + romfs_ctx.file_hash_table_size;

    buf.write(&header, sizeof(header));

    /* Write files. */
    cur_file = romfs_ctx.files;
    for (auto&e : entries) {
        buf.seek(cur_file->offset + ROMFS_FILEPARTITION_OFS);
        buf.write(e.data.data(), e.data.size());

        auto temp = cur_file;
        cur_file = cur_file->next;
        free(temp);
    }

    buf.seek(header.dirHashTableOff);
    buf.write(dir_hash_table.data(), romfs_ctx.dir_hash_table_size);

    buf.write(dir_table, romfs_ctx.dir_table_size);
    free(dir_table);

    buf.write(file_hash_table.data(), romfs_ctx.file_hash_table_size);

    buf.write(file_table, romfs_ctx.file_table_size);
    free(file_table);
}

auto romfs_build(const FileEntries& entries, u64 *out_size) -> std::vector<u8> {
    BufHelper buf;

    build_romfs_into_file(entries, buf);

    // Write Padding
    buf.seek(buf.buf.size());
    *out_size = buf.tell();
    write_padding(buf, buf.tell(), IVFC_HASH_BLOCK_SIZE);

    return buf.buf;
}

auto npdm_patch_kc(std::vector<u8>& npdm, u32 off, u32 size, u32 bitmask, u32 value) -> bool {
    const u32 pattern = BIT(bitmask) - 1;
    const u32 mask = BIT(bitmask) | pattern;

    for (u32 i = 0; i < size; i += 4) {
        u32 cup;
        std::memcpy(&cup, npdm.data() + off + i, sizeof(cup));
        if ((cup & mask) == pattern) {
            cup = value | pattern;
            std::memcpy(npdm.data() + off + i, &cup, sizeof(cup));
            return true;
        }
    }

    return false;
}

constexpr auto npdm_kernel_flags(CpuCoreMode mode) -> u32 {
    const u32 lowest_priority = mode == CpuCoreMode::Four ? 63 : 59;
    const u32 highest_priority = 28;
    const u32 lowest_cpu = 0;
    const u32 highest_cpu = mode == CpuCoreMode::Four ? 3 : 2;
    const u32 descriptor = (((highest_cpu << 8) | lowest_cpu) << 6 | highest_priority) << 6 | lowest_priority;
    return descriptor << 4;
}

static_assert((npdm_kernel_flags(CpuCoreMode::Three) | 0x7) == 0x020073B7);
static_assert((npdm_kernel_flags(CpuCoreMode::Four) | 0x7) == 0x030073F7);

// todo: manually build npdm
auto patch_npdm(std::vector<u8>& npdm, const NpdmPatch& patch) -> bool {
    constexpr u8 ADDRESS_SPACE_SHIFT = 1;
    constexpr u8 ADDRESS_SPACE_MASK = 0x7 << ADDRESS_SPACE_SHIFT;

    npdm::Meta meta{};
    npdm::Aci0 aci0{};
    npdm::Acid acid{};
    std::memcpy(&meta, npdm.data(), sizeof(meta));
    std::memcpy(&aci0, npdm.data() + meta.aci0_offset, sizeof(aci0));
    std::memcpy(&acid, npdm.data() + meta.acid_offset, sizeof(acid));

    // apply patch
    std::memcpy(meta.title_name, &patch.title_name, sizeof(meta.title_name));
    std::memcpy(meta.product_code, &patch.product_code, sizeof(patch.product_code));
    meta.flags = (meta.flags & ~ADDRESS_SPACE_MASK) | (static_cast<u8>(patch.address_space) << ADDRESS_SPACE_SHIFT);
    aci0.program_id = patch.tid;
    acid.program_id_min = patch.tid;
    acid.program_id_max = patch.tid;

    const auto kernel_flags = npdm_kernel_flags(patch.core_mode);
    const auto aci0_core_patched = npdm_patch_kc(npdm, meta.aci0_offset + aci0.kac_offset, aci0.kac_size, 3, kernel_flags);
    const auto acid_core_patched = npdm_patch_kc(npdm, meta.acid_offset + acid.kac_offset, acid.kac_size, 3, kernel_flags);

    const auto enable_svc_debug = [&patch](){
        if (patch.svc_debug_mode == ForwarderSvcDebugMode::Enabled) {
            return true;
        }
        if (patch.svc_debug_mode == ForwarderSvcDebugMode::Disabled) {
            return false;
        }

        // Atmosphere 1.8.0 updated the NPDM MiscFlags layout for HOS 19.0.0.
        // Preserve Sphaira's original behavior by selecting the new ForceDebug
        // bit automatically when that version (or newer) is detected.
        u64 ver{};
        if (R_FAILED(splInitialize())) {
            return false;
        }
        ON_SCOPE_EXIT(splExit());

        const auto SplConfigItem_ExosphereVersion = (SplConfigItem)65000;
        if (R_FAILED(splGetConfig(SplConfigItem_ExosphereVersion, &ver))) {
            return false;
        }
        ver >>= 40;
        return ver >= MAKEHOSVERSION(1,8,0);
    }();

    if (enable_svc_debug) {
        npdm_patch_kc(npdm, meta.aci0_offset + aci0.kac_offset, aci0.kac_size, 16, BIT(19));
        npdm_patch_kc(npdm, meta.acid_offset + acid.kac_offset, acid.kac_size, 16, BIT(19));
    }

    std::memcpy(npdm.data(), &meta, sizeof(meta));
    std::memcpy(npdm.data() + meta.aci0_offset, &aci0, sizeof(aci0));
    std::memcpy(npdm.data() + meta.acid_offset, &acid, sizeof(acid));
    return aci0_core_patched && acid_core_patched;
}

void patch_nacp(NacpStruct& nacp, const NcapPatch& patch) {
    // patch title
    if (!patch.name.empty()) {
        for (auto& lang : NacpLanguageEntries(nacp)) {
            std::strncpy(lang.name, patch.name.c_str(), sizeof(lang.name)-1);
        }
    }

    // patch author
    if (!patch.author.empty()) {
        for (auto& lang : NacpLanguageEntries(nacp)) {
            std::strncpy(lang.author, patch.author.c_str(), sizeof(lang.author)-1);
        }
    }

    // misc
    nacp.startup_user_account = patch.profile_selection ? 0x01 : 0x00;
    nacp.user_account_switch_lock = 0x00; // allow account switch
    nacp.add_on_content_registration_type = 0x01; // on demand
    nacp.screenshot = patch.screenshot ? 0x0 : 0x1;
    nacp.video_capture = patch.video_capture ? 0x2 : 0x0; // auto or disabled
    nacp.logo_type = 0x2; // Nintendo
    nacp.logo_handling = 0x0; // auto
    nacp.data_loss_confirmation = 0x0; // disable as we don't use saves
    nacp.required_network_service_license_on_launch = 0x0; // don't require linked account
    const char error_code[] = "greennx";
    static_assert(sizeof(error_code) <= 9);
    nacp.application_error_code_category = 0; // this is actually a char[8], not a u64 :)
    std::memcpy(&nacp.application_error_code_category, error_code, sizeof(error_code)-1);

    // update tid
    nacp.presence_group_id = patch.tid;
    nacp.save_data_owner_id = patch.tid;
    nacp.pseudo_device_id_seed = patch.tid;
    nacp.add_on_content_base_id = patch.tid ^ 0x1000;
    for (auto& id : nacp.local_communication_id) {
        id = patch.tid;
    }

    // enable play logging
    nacp.play_log_policy = 0x0; // open
    nacp.play_log_query_capability = 0x0;

    // disable save creation
    nacp.user_account_save_data_size = 0x0;
    nacp.user_account_save_data_journal_size = 0x0;
    nacp.device_save_data_size = 0x0;
    nacp.device_save_data_journal_size = 0x0;
    nacp.user_account_save_data_size_max = 0x0;
    nacp.user_account_save_data_journal_size_max = 0x0;
    nacp.device_save_data_size_max = 0x0;
    nacp.device_save_data_journal_size_max = 0x0;
}

void add_file_entry(FileEntries& entries, const char* name, const void* data, u64 size) {
    FileEntry entry;
    entry.name = name;
    entry.data.resize(size);
    std::memcpy(entry.data.data(), data, size);
    entries.emplace_back(entry);
}

auto build_ivfc_master_hash(const std::vector<u8>& level1) -> std::vector<u8> {
    std::vector<u8> hash(SHA256_HASH_SIZE);
    sha256CalculateHash(hash.data(), level1.data(), level1.size());
    return hash;
}

auto build_pfs0(const FileEntries& entries) -> std::vector<u8> {
    BufHelper buf;

    Pfs0Header header{};
    std::vector<Pfs0FileTable> file_table(entries.size());
    std::vector<char> string_table;

    u64 string_offset{};
    u64 data_offset{};

    for (u32 i = 0; i < entries.size(); i++) {
        file_table[i].data_offset = data_offset;
        file_table[i].data_size = entries[i].data.size();
        file_table[i].name_offset = string_offset;
        file_table[i].padding = 0;

        string_table.resize(string_offset + entries[i].name.length() + 1);
        std::memcpy(string_table.data() + string_offset, entries[i].name.c_str(), entries[i].name.length() + 1);

        data_offset += entries[i].data.size();
        string_offset += entries[i].name.length() + 1;
    }

    // align table
    string_table.resize((string_table.size() + 0x1F) & ~0x1F);

    header.magic = 0x30534650;
    header.total_files = entries.size();
    header.string_table_size = string_table.size();
    header.padding = 0;

    buf.write(&header, sizeof(header));
    buf.write(file_table.data(), sizeof(Pfs0FileTable) * file_table.size());
    buf.write(string_table.data(), string_table.size());

    for (const auto&e : entries) {
        buf.write(e.data.data(), e.data.size());
    }

    return buf.buf;
}

auto build_pfs0_hash_table(const std::vector<u8>& pfs0, u32 block_size) -> std::vector<u8> {
    BufHelper buf;
    u8 hash[SHA256_HASH_SIZE];
    u32 read_size = block_size;

    for (u32 i = 0; i < pfs0.size(); i += read_size) {
        if (i + read_size >= pfs0.size()) {
            read_size = pfs0.size() - i;
        }
        sha256CalculateHash(hash, pfs0.data() + i, read_size);
        buf.write(hash, sizeof(hash));
    }

    return buf.buf;
}

auto build_pfs0_master_hash(const std::vector<u8>& pfs0_hash_table) -> std::vector<u8> {
    std::vector<u8> hash(SHA256_HASH_SIZE);
    sha256CalculateHash(hash.data(), pfs0_hash_table.data(), pfs0_hash_table.size());
    return hash;
}

void write_nca_padding(BufHelper& buf) {
    write_padding(buf, buf.tell(), 0x200);
}

void nca_encrypt_header(nca::Header* header, const u8* key) {
    Aes128XtsContext ctx{};
    aes128XtsContextCreate(&ctx, key, key + 0x10, true);

    u8 sector{};
    for (u64 pos = 0; pos < 0xC00; pos += 0x200) {
        aes128XtsContextResetSector(&ctx, sector++, true);
        aes128XtsEncrypt(&ctx, (u8*)header + pos, (const u8*)header + pos, 0x200);
    }
}

void write_nca_section(nca::Header& nca_header, u8 index, u64 start, u64 end) {
    auto& section = nca_header.fs_table[index];
    section.media_start_offset = start / 0x200; // 0xC00 / 0x200
    section.media_end_offset = end / 0x200; // Section end offset / 200
    section._0x8[0] = 0x1; // Always 1
}

void write_nca_fs_header_pfs0(nca::Header& nca_header, u8 index, const std::vector<u8>& master_hash, u64 hash_table_size, u32 block_size) {
    auto& fs_header = nca_header.fs_header[index];
    fs_header.hash_type = nca::HashType_HierarchicalSha256;
    fs_header.fs_type = nca::FileSystemType_PFS0;
    fs_header.version = 0x2; // Always 2
    fs_header.hash_data.hierarchical_sha256_data.layer_count = 0x2;
    fs_header.hash_data.hierarchical_sha256_data.block_size = block_size;
    fs_header.encryption_type = nca::EncryptionType_None;
    fs_header.hash_data.hierarchical_sha256_data.hash_layer.size = hash_table_size;
    std::memcpy(fs_header.hash_data.hierarchical_sha256_data.master_hash, master_hash.data(), master_hash.size());
    sha256CalculateHash(&nca_header.fs_header_hash[index], &fs_header, sizeof(fs_header));
}

void write_nca_fs_header_romfs(nca::Header& nca_header, u8 index) {
    auto& fs_header = nca_header.fs_header[index];
    fs_header.hash_type = nca::HashType_HierarchicalIntegrity;
    fs_header.fs_type = nca::FileSystemType_RomFS;
    fs_header.version = 0x2; // Always 2
    fs_header.hash_data.integrity_meta_info.magic = 0x43465649;
    fs_header.hash_data.integrity_meta_info.version = 0x20000; // Always 0x20000
    fs_header.hash_data.integrity_meta_info.master_hash_size = SHA256_HASH_SIZE;
    fs_header.hash_data.integrity_meta_info.info_level_hash.max_layers = 0x7;
    fs_header.encryption_type = nca::EncryptionType_None;
    fs_header.hash_data.integrity_meta_info.info_level_hash.levels[5].block_size = 0x0E; // 0x4000
    sha256CalculateHash(&nca_header.fs_header_hash[index], &fs_header, sizeof(fs_header));
}

void write_nca_pfs0(nca::Header& nca_header, u8 index, const FileEntries& entries, u32 block_size, BufHelper& buf) {
    const auto pfs0 = build_pfs0(entries);
    const auto pfs0_hash_table = build_pfs0_hash_table(pfs0, block_size);
    const auto pfs0_master_hash = build_pfs0_master_hash(pfs0_hash_table);

    buf.write(pfs0_hash_table.data(), pfs0_hash_table.size());
    const auto padding_size = write_padding(buf, pfs0_hash_table.size(), PFS0_PADDING_SIZE);

    nca_header.fs_header[index].hash_data.hierarchical_sha256_data.pfs0_layer.offset = pfs0_hash_table.size() + padding_size;
    nca_header.fs_header[index].hash_data.hierarchical_sha256_data.pfs0_layer.size = pfs0.size();

    buf.write(pfs0.data(), pfs0.size());
    write_nca_padding(buf);

    const auto section_start = index == 0 ? sizeof(nca_header) : nca_header.fs_table[index-1].media_end_offset * 0x200;
    write_nca_section(nca_header, index, section_start, buf.tell());
    write_nca_fs_header_pfs0(nca_header, index, pfs0_master_hash, pfs0_hash_table.size(), block_size);
}

auto ivfc_create_level(const std::vector<u8>& src) -> std::vector<u8> {
    BufHelper buf;
    u8 hash[SHA256_HASH_SIZE];
    u64 read_size = IVFC_HASH_BLOCK_SIZE;

    for (u32 i = 0; i < src.size(); i += read_size) {
        if (i + read_size >= src.size()) {
            read_size = src.size() - i;
        }
        sha256CalculateHash(hash, src.data() + i, read_size);
        buf.write(hash, sizeof(hash));
    }

    write_padding(buf, buf.tell(), IVFC_HASH_BLOCK_SIZE);

    return buf.buf;
}

void write_nca_romfs(nca::Header& nca_header, u8 index, const FileEntries& entries, u32 block_size, BufHelper& buf) {
    auto& fs_header = nca_header.fs_header[index];
    auto& meta_info = fs_header.hash_data.integrity_meta_info;
    auto& info_level_hash = meta_info.info_level_hash;

    std::vector<u8> ivfc[IVFC_MAX_LEVEL];

    ivfc[5] = romfs_build(entries, &info_level_hash.levels[5].hash_data_size);

    for (int b = 4; b >= 0; b--) {
        ivfc[b] = ivfc_create_level(ivfc[b + 1]);
        info_level_hash.levels[b].hash_data_size = ivfc[b].size();
        info_level_hash.levels[b].block_size = 0x0E; // 0x4000
    }

    info_level_hash.levels[0].logical_offset = 0;
    for (int i = 1; i <= 5; i++) {
        info_level_hash.levels[i].logical_offset = info_level_hash.levels[i - 1].logical_offset + info_level_hash.levels[i - 1].hash_data_size;
    }

    for (const auto& iv : ivfc) {
        buf.write(iv.data(), iv.size());
    }

    write_nca_padding(buf);

    const auto ivfc_master_hash = build_ivfc_master_hash(ivfc[0]);
    std::memcpy(meta_info.master_hash, ivfc_master_hash.data(), sizeof(meta_info.master_hash));

    const auto section_start = index == 0 ? sizeof(nca_header) : nca_header.fs_table[index-1].media_end_offset * 0x200;
    write_nca_section(nca_header, index, section_start, buf.tell());
    write_nca_fs_header_romfs(nca_header, index);
}

void write_nca_header_encypted(nca::Header& nca_header, u64 tid, const keys::Keys& keys, nca::ContentType type, BufHelper& buf) {
    nca_header.magic = NCA3_MAGIC;
    nca_header.distribution_type = nca::DistributionType_System;
    nca_header.content_type = type;
    nca_header.program_id = tid;
    nca_header.sdk_version = 0x000C1100;
    nca_header.size = buf.tell();

    nca_encrypt_header(&nca_header, keys.header_key);
    buf.seek(0);
    buf.write(&nca_header, sizeof(nca_header));
}

auto create_program_nca(u64 tid, const keys::Keys& keys, const FileEntries& exefs, const FileEntries& romfs, const FileEntries& logo) -> NcaEntry {
    BufHelper buf;
    nca::Header nca_header{};
    buf.write(&nca_header, sizeof(nca_header));

    write_nca_pfs0(nca_header, 0, exefs, PFS0_EXEFS_HASH_BLOCK_SIZE, buf);
    write_nca_romfs(nca_header, 1, romfs, IVFC_HASH_BLOCK_SIZE, buf);
    // only write logo if set (can only 1 file be added?)
    if (logo.size() == 2 && !logo[0].data.empty() && !logo[1].data.empty()) {
        write_nca_pfs0(nca_header, 2, logo, PFS0_LOGO_HASH_BLOCK_SIZE, buf);
    }
    write_nca_header_encypted(nca_header, tid, keys, nca::ContentType_Program, buf);

    return {buf, NcmContentType_Program};
}

auto create_control_nca(u64 tid, const keys::Keys& keys, const FileEntries& romfs) -> NcaEntry{
    nca::Header nca_header{};
    BufHelper buf;
    buf.write(&nca_header, sizeof(nca_header));

    write_nca_romfs(nca_header, 0, romfs, IVFC_HASH_BLOCK_SIZE, buf);
    write_nca_header_encypted(nca_header, tid, keys, nca::ContentType_Control, buf);

    return {buf, NcmContentType_Control};
}

auto create_meta_nca(u64 tid, const keys::Keys& keys, NcmStorageId storage_id, const std::vector<NcaEntry>& ncas) -> NcaMetaEntry {
    CnmtHeader cnmt_header{};
    NcmApplicationMetaExtendedHeader cnmt_extended{};
    NcmPackagedContentInfo packaged_content_info[2]{};
    u8 digest[0x20]{};
    BufHelper buf;

    cnmt_header.title_id = tid;
    cnmt_header.title_version = 0; // todo: parse nacp.disaply_version
    cnmt_header.meta_type = NcmContentMetaType_Application;
    cnmt_header.meta_header.extended_header_size = sizeof(cnmt_extended);
    cnmt_header.meta_header.content_count = 0x2; // program + control
    cnmt_header.meta_header.content_meta_count = 0x1; // only 1 meta
    cnmt_header.meta_header.attributes = 0x0;
    cnmt_header.meta_header.storage_id = storage_id;
    cnmt_extended.patch_id = cnmt_header.title_id | 0x800;

    for (u32 i = 0; i < ncas.size(); i++) {
        std::memcpy(packaged_content_info[i].hash, ncas[i].hash, sizeof(packaged_content_info[i].hash));
        std::memcpy(&packaged_content_info[i].info.content_id, ncas[i].hash, sizeof(packaged_content_info[i].info.content_id));
        packaged_content_info[i].info.content_type = ncas[i].type;
        ncmU64ToContentInfoSize(ncas[i].data.size(), &packaged_content_info[i].info);
    }

    // create control
    BufHelper cnmt_buf;
    cnmt_buf.write(&cnmt_header, sizeof(cnmt_header));
    cnmt_buf.write(&cnmt_extended, sizeof(cnmt_extended));
    cnmt_buf.write(&packaged_content_info, sizeof(packaged_content_info));
    cnmt_buf.write(digest, sizeof(digest));

    FileEntries cnmt;
    char cnmt_name[34];
    std::snprintf(cnmt_name, sizeof(cnmt_name), "Application_%016lX.cnmt", tid);
    add_file_entry(cnmt, cnmt_name, cnmt_buf.buf.data(), cnmt_buf.buf.size());

    nca::Header nca_header{};
    buf.write(&nca_header, sizeof(nca_header));
    write_nca_pfs0(nca_header, 0, cnmt, PFS0_META_HASH_BLOCK_SIZE, buf);
    write_nca_header_encypted(nca_header, tid, keys, nca::ContentType_Meta, buf);

    // entry
    NcaMetaEntry entry{buf, NcmContentType_Meta};

    // header
    entry.content_meta_header = cnmt_header.meta_header;
    entry.content_meta_header.content_count++;
    entry.content_meta_header.storage_id = 0;

    // key
    entry.content_meta_key.id = cnmt_header.title_id;
    entry.content_meta_key.version = cnmt_header.title_version;
    entry.content_meta_key.type = cnmt_header.meta_type;
    entry.content_meta_key.install_type = NcmContentInstallType_Full;
    std::memset(entry.content_meta_key.padding, 0, sizeof(entry.content_meta_key.padding));

    // record
    entry.content_storage_record.key = entry.content_meta_key;
    entry.content_storage_record.storage_id = storage_id;
    std::memset(entry.content_storage_record.padding, 0, sizeof(entry.content_storage_record.padding));

    // data
    entry.content_meta_data.header = entry.content_meta_header;
    entry.content_meta_data.extended = cnmt_extended;

    // meta content info
    std::memcpy(&entry.content_meta_data.infos[0].content_id, entry.nca_entry.hash, sizeof(entry.content_meta_data.infos[0].content_id));
    entry.content_meta_data.infos[0].content_type = entry.nca_entry.type;
    entry.content_meta_data.infos[0].attr = 0;
    ncmU64ToContentInfoSize(cnmt_buf.buf.size(), &entry.content_meta_data.infos[0]);
    entry.content_meta_data.infos[0].id_offset = 0;

    // program + control content info
    entry.content_meta_data.infos[1] = packaged_content_info[0].info;
    entry.content_meta_data.infos[2] = packaged_content_info[1].info;

    return entry;
}

constexpr const char* kNroPath = "sdmc:/switch/green-nx/green-nx.nro";
constexpr int kIconSize = 256;

const u8 kHeaderKekSource[0x10] = {0x1F, 0x12, 0x91, 0x3A, 0x4A, 0xCB,
                                   0xF0, 0x0D, 0x4C, 0xDE, 0x3A, 0xF6,
                                   0xD5, 0x23, 0x88, 0x2A};
const u8 kHeaderKeySource[0x20] = {
    0x5A, 0x3E, 0xD8, 0x4F, 0xDE, 0xC0, 0xD8, 0x26, 0x31, 0xF7, 0xE2,
    0x5D, 0x19, 0x7B, 0xF5, 0xD0, 0x1C, 0x9B, 0x7B, 0xFA, 0xF6, 0x28,
    0x18, 0x3D, 0x71, 0xF6, 0x4D, 0x73, 0xF1, 0x50, 0xB9, 0xD2};

Result derive_keys(keys::Keys& out) {
    u8 header_kek[0x20];
    R_TRY(splCryptoGenerateAesKek(kHeaderKekSource, 0, 0, header_kek));
    R_TRY(splCryptoGenerateAesKey(header_kek, kHeaderKeySource,
                                  out.header_key));
    return splCryptoGenerateAesKey(header_kek, kHeaderKeySource + 0x10,
                                   out.header_key + 0x10);
}

std::string launch_args(const std::string& title_id) {
    return std::string(kNroPath) + " --appid=" + title_id;
}

// Same id scheme as sphaira, so one .nro can back any number of forwarders.
u64 title_id_for(const std::string& title_id) {
    const std::string hashed = kNroPath + launch_args(title_id);
    u64 hash[SHA256_HASH_SIZE / sizeof(u64)];
    sha256CalculateHash(hash, hashed.data(), hashed.size());
    return 0x0500000000000000 | (hash[0] & 0x00FFFFFFFFFFF000);
}

Service g_app_manager;

Result ns_open() {
    R_TRY(nsInitialize());
    const Result rc = nsGetApplicationManagerInterface(&g_app_manager);
    if (R_FAILED(rc)) nsExit();
    return rc;
}

void ns_close() {
    serviceClose(&g_app_manager);
    nsExit();
}

Result push_application_record(u64 tid,
                               const ncm::ContentStorageRecord* record) {
    const struct {
        u8 last_modified_event;
        u8 padding[0x7];
        u64 tid;
    } in = {0x3 /* installed */, {0}, tid};
    return serviceDispatchIn(
        &g_app_manager, 16, in,
        .buffer_attrs = {SfBufferAttr_HipcMapAlias | SfBufferAttr_In},
        .buffers = {{record, sizeof(*record)}});
}

Result invalidate_control_cache(u64 tid) {
    return serviceDispatchIn(&g_app_manager, 404, tid);
}

// The app's own NACP is the template: it already carries valid defaults.
bool read_own_nacp(NacpStruct& nacp) {
    FILE* f = std::fopen(kNroPath, "rb");
    if (!f) return false;
    ON_SCOPE_EXIT(std::fclose(f));
    NroStart start;
    NroHeader header;
    NroAssetHeader assets;
    if (std::fread(&start, sizeof(start), 1, f) != 1 ||
        std::fread(&header, sizeof(header), 1, f) != 1 ||
        std::fseek(f, header.size, SEEK_SET) != 0 ||
        std::fread(&assets, sizeof(assets), 1, f) != 1 ||
        assets.magic != NROASSETHEADER_MAGIC ||
        assets.nacp.size < sizeof(nacp) ||
        std::fseek(f, header.size + assets.nacp.offset, SEEK_SET) != 0)
        return false;
    return std::fread(&nacp, sizeof(nacp), 1, f) == 1;
}

// HOME wants a 256x256 JPEG; store art is neither reliably square nor JPEG.
bool make_icon(const std::string& image, std::vector<u8>& out) {
    SDL_RWops* rw = SDL_RWFromConstMem(image.data(), image.size());
    SDL_Surface* src = rw ? IMG_Load_RW(rw, 1) : nullptr;
    if (!src) return false;
    ON_SCOPE_EXIT(SDL_FreeSurface(src));
    SDL_Surface* icon = SDL_CreateRGBSurfaceWithFormat(
        0, kIconSize, kIconSize, 24, SDL_PIXELFORMAT_RGB24);
    if (!icon) return false;
    ON_SCOPE_EXIT(SDL_FreeSurface(icon));
    const int side = src->w < src->h ? src->w : src->h;
    SDL_Rect crop = {(src->w - side) / 2, (src->h - side) / 2, side, side};
    SDL_Rect dst = {0, 0, kIconSize, kIconSize};
    if (SDL_BlitScaled(src, &crop, icon, &dst) != 0) return false;

    constexpr const char* kTemp = "sdmc:/switch/green-nx/icon-tmp.jpg";
    if (IMG_SaveJPG(icon, kTemp, 90) != 0) return false;
    ON_SCOPE_EXIT(std::remove(kTemp));
    FILE* f = std::fopen(kTemp, "rb");
    if (!f) return false;
    ON_SCOPE_EXIT(std::fclose(f));
    std::fseek(f, 0, SEEK_END);
    out.resize(std::ftell(f));
    std::fseek(f, 0, SEEK_SET);
    return !out.empty() && std::fread(out.data(), out.size(), 1, f) == 1;
}

Result install_title(const std::string& title_id, const std::string& name,
                     const std::vector<u8>& icon, NacpStruct& nacp) {
    constexpr NcmStorageId storage_id = NcmStorageId_SdCard;
    const u64 tid = title_id_for(title_id);
    const std::string args = launch_args(title_id);

    keys::Keys keys;
    R_TRY(derive_keys(keys));

    std::vector<NcaEntry> nca_entries;
    {
        FileEntries exefs;
        add_file_entry(exefs, "main", gnx_hbl_main,
                       gnx_hbl_main_end - gnx_hbl_main);
        add_file_entry(exefs, "main.npdm", gnx_hbl_npdm,
                       gnx_hbl_npdm_end - gnx_hbl_npdm);

        FileEntries romfs;
        add_file_entry(romfs, "/nextArgv", args.data(), args.length());
        add_file_entry(romfs, "/nextNroPath", kNroPath, std::strlen(kNroPath));

        NpdmPatch npdm_patch;
        npdm_patch.tid = tid;
        if (!patch_npdm(exefs[1].data, npdm_patch))
            return MAKERESULT(Module_Libnx, LibnxError_BadInput);
        nca_entries.emplace_back(
            create_program_nca(tid, keys, exefs, romfs, FileEntries{}));
    }
    {
        NcapPatch nacp_patch{};
        nacp_patch.tid = tid;
        nacp_patch.name = name;
        nacp_patch.author = "green-nx";
        patch_nacp(nacp, nacp_patch);

        FileEntries romfs;
        add_file_entry(romfs, "/control.nacp", &nacp, sizeof(nacp));
        add_file_entry(romfs, "/icon_AmericanEnglish.dat", icon.data(),
                       icon.size());
        nca_entries.emplace_back(create_control_nca(tid, keys, romfs));
    }

    const NcaMetaEntry meta =
        create_meta_nca(tid, keys, storage_id, nca_entries);
    nca_entries.emplace_back(meta.nca_entry);

    {
        NcmContentStorage cs;
        R_TRY(ncmOpenContentStorage(&cs, storage_id));
        ON_SCOPE_EXIT(ncmContentStorageClose(&cs));
        for (const NcaEntry& entry : nca_entries) {
            NcmContentId content_id;
            NcmPlaceHolderId placeholder_id;
            std::memcpy(&content_id, entry.hash, sizeof(content_id));
            R_TRY(ncmContentStorageGeneratePlaceHolderId(&cs, &placeholder_id));
            ncmContentStorageDeletePlaceHolder(&cs, &placeholder_id);
            R_TRY(ncmContentStorageCreatePlaceHolder(
                &cs, &content_id, &placeholder_id, entry.data.size()));
            R_TRY(ncmContentStorageWritePlaceHolder(
                &cs, &placeholder_id, 0, entry.data.data(), entry.data.size()));
            ncmContentStorageDelete(&cs, &content_id);
            R_TRY(ncmContentStorageRegister(&cs, &content_id, &placeholder_id));
        }
    }
    {
        NcmContentMetaDatabase db;
        R_TRY(ncmOpenContentMetaDatabase(&db, storage_id));
        ON_SCOPE_EXIT(ncmContentMetaDatabaseClose(&db));
        R_TRY(ncmContentMetaDatabaseSet(&db, &meta.content_meta_key,
                                        &meta.content_meta_data,
                                        sizeof(meta.content_meta_data)));
        R_TRY(ncmContentMetaDatabaseCommit(&db));
    }

    nsDeleteApplicationEntity(tid);
    R_TRY(push_application_record(tid, &meta.content_storage_record));
    invalidate_control_cache(tid);
    return 0;
}

std::string result_error(const char* what, Result rc) {
    char text[96];
    std::snprintf(text, sizeof(text), "%s failed (%04d-%04d)", what,
                  2000 + R_MODULE(rc), R_DESCRIPTION(rc));
    return text;
}

}  // namespace

bool on_emummc() {
    // Atmosphere's ExosphereEmummcType: non-zero when booted from emuMMC.
    constexpr auto kExosphereEmummcType = static_cast<SplConfigItem>(65007);
    if (R_FAILED(splInitialize())) return false;
    u64 type = 0;
    const Result rc = splGetConfig(kExosphereEmummcType, &type);
    splExit();
    return R_SUCCEEDED(rc) && type != 0;
}

bool installed(const std::string& title_id) {
    if (R_FAILED(nsInitialize())) return false;
    s32 count = 0;
    const Result rc =
        nsCountApplicationContentMeta(title_id_for(title_id), &count);
    nsExit();
    return R_SUCCEEDED(rc) && count > 0;
}

std::string install(const std::string& title_id, const std::string& name,
                    const std::string& image) {
    if (!on_emummc()) return "Home screen shortcuts need emuMMC";
    auto nacp = std::make_unique<NacpStruct>();
    if (!read_own_nacp(*nacp)) return "Could not read green-nx.nro";
    std::vector<u8> icon;
    if (!make_icon(image, icon)) return "Could not prepare the icon";

    Result rc = splCryptoInitialize();
    if (R_FAILED(rc)) return result_error("spl", rc);
    ON_SCOPE_EXIT(splCryptoExit());
    rc = ncmInitialize();
    if (R_FAILED(rc)) return result_error("ncm", rc);
    ON_SCOPE_EXIT(ncmExit());
    rc = ns_open();
    if (R_FAILED(rc)) return result_error("ns", rc);
    ON_SCOPE_EXIT(ns_close());

    rc = install_title(title_id, name, icon, *nacp);
    return R_FAILED(rc) ? result_error("Install", rc) : std::string();
}

std::string remove(const std::string& title_id) {
    if (!on_emummc()) return "Home screen shortcuts need emuMMC";
    Result rc = nsInitialize();
    if (R_FAILED(rc)) return result_error("ns", rc);
    ON_SCOPE_EXIT(nsExit());
    rc = nsDeleteApplicationCompletely(title_id_for(title_id));
    return R_FAILED(rc) ? result_error("Remove", rc) : std::string();
}

}  // namespace gnx::forwarder

#else  // PC harness: no home screen to add anything to.

namespace gnx::forwarder {
bool on_emummc() { return false; }
bool installed(const std::string&) { return false; }
std::string install(const std::string&, const std::string&,
                    const std::string&) {
    return "Only available on the Switch";
}
std::string remove(const std::string&) {
    return "Only available on the Switch";
}
}  // namespace gnx::forwarder

#endif
