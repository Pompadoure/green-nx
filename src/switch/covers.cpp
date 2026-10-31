#include "covers.hpp"

#include <sys/stat.h>

#include <cstdio>
#include <fstream>

#include "../core/http.hpp"

namespace gnx {

namespace {

// Roughly a dozen rows' worth of Home plus the grid: enough that scrolling
// back is instant, while keeping VRAM bounded across a 589-title library.
constexpr size_t kMaxTextures = 220;

}  // namespace

Covers::Covers(gfx::Gfx& gfx, std::string cache_dir)
    : gfx_(gfx), cache_dir_(std::move(cache_dir)) {
    mkdir(cache_dir_.c_str(), 0755);
    disk_thread_ = std::thread(&Covers::disk_worker, this);
    net_thread_ = std::thread(&Covers::net_worker, this);
}

Covers::~Covers() {
    quit_ = true;
    wake_.notify_all();
    if (disk_thread_.joinable()) disk_thread_.join();
    if (net_thread_.joinable()) net_thread_.join();
    for (Done& done : done_)
        if (done.surface) SDL_FreeSurface(done.surface);
    for (auto& [key, texture] : textures_)
        if (texture) SDL_DestroyTexture(texture);
}

SDL_Texture* Covers::get(const std::string& title_id, const std::string& url) {
    auto found = textures_.find(title_id);
    if (found != textures_.end()) {
        last_used_[title_id] = SDL_GetTicks();
        return found->second;
    }
    if (url.empty()) return nullptr;

    std::lock_guard<std::mutex> lock(mutex_);
    if (!pending_.count(title_id)) {
        pending_.insert(title_id);
        disk_jobs_.push_back({title_id, url});
        wake_.notify_all();
    }
    return nullptr;
}

void Covers::pump() {
    for (int budget = 0; budget < 2; ++budget) {
        Done done;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (done_.empty()) return;
            done = std::move(done_.front());
            done_.pop_front();
        }
        // Negative results are cached as nullptr so we don't retry every frame.
        textures_[done.title_id] = gfx_.texture_from_surface(done.surface);
        last_used_[done.title_id] = SDL_GetTicks();
    }

    while (textures_.size() > kMaxTextures) {
        auto oldest = last_used_.begin();
        for (auto it = last_used_.begin(); it != last_used_.end(); ++it)
            if (it->second < oldest->second) oldest = it;
        auto texture = textures_.find(oldest->first);
        if (texture != textures_.end()) {
            if (texture->second) SDL_DestroyTexture(texture->second);
            textures_.erase(texture);
        }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            pending_.erase(oldest->first);  // reloadable from the SD card
        }
        last_used_.erase(oldest);
    }
}

void Covers::drop_textures() {
    for (auto& [key, texture] : textures_)
        if (texture) SDL_DestroyTexture(texture);
    textures_.clear();
    last_used_.clear();
    std::lock_guard<std::mutex> lock(mutex_);
    pending_.clear();  // allow re-queue after the renderer is rebuilt
    for (Done& done : done_)
        if (done.surface) SDL_FreeSurface(done.surface);
    done_.clear();
}

void Covers::finish(const std::string& title_id,
                    const std::vector<char>& bytes) {
    SDL_Surface* surface =
        bytes.empty() ? nullptr
                      : gfx::Gfx::decode_image(bytes.data(), bytes.size());
    std::lock_guard<std::mutex> lock(mutex_);
    done_.push_back({title_id, surface});
}

void Covers::disk_worker() {
    while (!quit_) {
        Job job;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            wake_.wait(lock, [&] { return quit_ || !disk_jobs_.empty(); });
            if (quit_) return;
            job = std::move(disk_jobs_.back());
            disk_jobs_.pop_back();
        }

        std::ifstream cached(cache_dir_ + "/" + job.title_id + ".img",
                             std::ios::binary);
        if (cached) {
            std::vector<char> bytes;
            bytes.assign(std::istreambuf_iterator<char>(cached), {});
            finish(job.title_id, bytes);
        } else {
            std::lock_guard<std::mutex> lock(mutex_);
            net_jobs_.push_back(std::move(job));
            wake_.notify_all();
        }
    }
}

void Covers::net_worker() {
    Http http;
    http.set_abort_flag(&quit_);  // unblock in-flight download on shutdown
    while (!quit_) {
        Job job;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            wake_.wait(lock, [&] { return quit_ || !net_jobs_.empty(); });
            if (quit_) return;
            job = std::move(net_jobs_.back());
            net_jobs_.pop_back();
        }

        std::vector<char> bytes;
        try {
            HttpResponse response = http.get(job.url);
            if (response.ok() && !response.body.empty()) {
                bytes.assign(response.body.begin(), response.body.end());
                std::ofstream out(cache_dir_ + "/" + job.title_id + ".img",
                                  std::ios::binary | std::ios::trunc);
                out.write(bytes.data(),
                          static_cast<std::streamsize>(bytes.size()));
            }
        } catch (const std::exception&) {
            // Leave bytes empty; pump() caches the miss.
        }
        finish(job.title_id, bytes);
    }
}

}  // namespace gnx
