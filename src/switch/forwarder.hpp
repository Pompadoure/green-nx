#pragma once

#include <string>

namespace gnx::forwarder {

// True when booted from emuMMC, the only place shortcuts are allowed.
bool on_emummc();

// Whether the title already has a shortcut on the HOME menu.
bool installed(const std::string& title_id);

// Add or remove a HOME menu shortcut that starts the title directly. `image`
// is the raw cover image, any format SDL_image reads. Blocking, so call from a
// worker thread. Returns an empty string on success, else a short error.
std::string install(const std::string& title_id, const std::string& name,
                    const std::string& image);
std::string remove(const std::string& title_id);

}  // namespace gnx::forwarder
