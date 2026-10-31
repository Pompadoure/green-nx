#pragma once

#include <SDL2/SDL.h>

#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "gfx.hpp"

namespace gnx {

// Box-art cache: one worker reads covers from the SD card, another downloads
// the rest, and both decode off the render thread. The main thread only uploads
// the decoded surfaces (SDL textures must be created on the render thread).
// Both queues run newest first, so what is on screen after a fast scroll loads
// ahead of the covers that were scrolled past.
class Covers {
public:
    Covers(gfx::Gfx& gfx, std::string cache_dir);
    ~Covers();

    // Returns the texture if ready, nullptr otherwise (and queues the fetch).
    SDL_Texture* get(const std::string& title_id, const std::string& url);

    // Main-thread pump: turn finished downloads into textures (a few per frame).
    void pump();

    // Destroy all cached textures (call before the renderer is torn down for a
    // deko3d stream). They reload lazily from the on-disk cache afterwards.
    void drop_textures();

private:
    void disk_worker();
    void net_worker();
    void finish(const std::string& title_id, const std::vector<char>& bytes);

    gfx::Gfx& gfx_;
    std::string cache_dir_;

    std::unordered_map<std::string, SDL_Texture*> textures_;
    std::unordered_map<std::string, Uint32> last_used_;
    std::unordered_set<std::string> pending_;

    struct Job {
        std::string title_id;
        std::string url;
    };
    struct Done {
        std::string title_id;
        SDL_Surface* surface;  // nullptr: nothing usable for this title
    };

    std::mutex mutex_;
    std::condition_variable wake_;
    std::deque<Job> disk_jobs_;
    std::deque<Job> net_jobs_;
    std::deque<Done> done_;
    std::atomic<bool> quit_{false};
    std::thread disk_thread_;
    std::thread net_thread_;
};

}  // namespace gnx
